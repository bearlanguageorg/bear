// codegen.v — bytecode code generator for VuurRaaf.
//
// Compiles a parsed program into a VROBJ object file: flat bytecode plus a
// symbol per function and a relocation per call site. Call targets are left as
// relocations and resolved by the linker, so functions may live in other files.
module compiler

import obj

struct Fixup {
	name string
	off  u32
}

// LoopCtx records where `break` and `continue` should jump while generating
// the body of a loop. For `for` loops `continue` targets the increment, not
// the condition check, so the loop variable still advances.
struct LoopCtx {
	break_l    string
	continue_l string
}

struct Gen {
mut:
	code      []u8
	strings   []string
	str_map   map[string]int
	symbols   []obj.Symbol
	relocs    []obj.Reloc
	locals    map[string]int
	types     map[string]string      // local name -> declared struct type ('' = unknown)
	structs   map[string][]string    // declared struct name -> field list
	enums     map[string][]string    // enum name -> variant list
	lam_counter int // anonymous function counter
	enum_vals map[string]int         // 'Enum.variant' -> integer value
	consts    map[string]Expr       // constant name -> value expression (int/bool/string/float)
	lines     []obj.LineInfo         // code offset -> source line (debug info)
	dbg_locals []obj.DbgLocal        // per-function local name -> stack slot (debugger)
	local_cnt int
	argc      int
	cur_fn    string
	labels    map[string]int
	fixups    []Fixup
	loops     []LoopCtx
	enter_off u32
	next_lbl  int
	modules   map[string]bool // imported module names (bare `import os`)
	fn_names  map[string]bool // top-level function names usable as closure values
	captures  []string        // enclosing locals captured by the closure being compiled
	defers    []Stmt        // deferred statements of the current function (in order)
	has_defers bool          // current function registers deferred cleanup
	defer_ret_slot int      // hidden local holding the return value while defers run
	defer_value_seen bool   // a `return expr` (value) appeared, so restore+retv after defers
	cur_defer_label string // label of the current function's deferred-cleanup block
	namer_id  int            // unique-id source for generated label names
}

fn gen(prog Program) !obj.Obj {
	mut g := Gen{}
	// register enums first so their values are available everywhere
	for ed in prog.enums {
		if ed.name in g.enums {
			return error('duplicate enum declaration "${ed.name}"')
		}
		g.enums[ed.name] = ed.variants
		for i, v in ed.variants {
			g.enum_vals['${ed.name}.${v}'] = i
		}
	}
	// register constants
	for cd in prog.consts {
		if cd.name in g.consts {
			return error('duplicate constant declaration "${cd.name}"')
		}
		// constants must be compile-time literals: int, bool, string, or float.
		// The value expression is stored and emitted at each use site, so string
		// and float constants get the right opcode (op_push_s / op_push_f)
		// while int/bool constants stay as op_push_i.
		match cd.value.kind {
			.int_lit, .bool_lit, .str_lit, .float_lit {
				g.consts[cd.name] = cd.value
			}
			else {
				return error('constant "${cd.name}" must be an integer, boolean, string, or float literal (line ${cd.line})')
			}
		}
	}
	// register struct declarations
	for sd in prog.structs {
		if sd.name in g.structs {
			return error('duplicate struct declaration "${sd.name}"')
		}
		g.structs[sd.name] = sd.fields
	}
	// compile imported files and merge their objects. Bare module imports
	// (`import os`) prefix the module's function symbols and internal call
	// relocations with "os.", so programs call os.exists(...) and modules can
	// never collide with each other or with the program's own functions.
	for imp in prog.imports {
		mod_name := imp.name
		prefix := if mod_name.len > 0 { mod_name + '.' } else { '' }
		imported := compile_file(resolve_import(imp.path)!)!
		if mod_name.len > 0 {
			g.modules[mod_name] = true
		}
		// the imported object's own symbol names (for rewriting call sites)
		mut own := map[string]bool{}
		for s in imported.symbols {
			own[s.name] = true
		}
		// append imported bytecode first so symbol entries can be rebased
		code_off := g.code.len
		g.code << imported.code
		// merge symbols from the imported object (prefixed and rebased: entries
		// are relative to the imported code, which now sits at code_off)
		for s in imported.symbols {
			g.symbols << obj.Symbol{ name: prefix + s.name, entry: code_off + s.entry }
		}
		// merge strings
		for s in imported.strings {
			g.strings << s
		}
		// adjust relocations (and prefix module-internal call targets)
		for r in imported.relocs {
			mut rname := r.name
			if r.kind == 0 && prefix.len > 0 && r.name in own {
				rname = prefix + r.name
			}
			g.relocs << obj.Reloc{ offset: u32(code_off) + r.offset, name: rname, kind: r.kind }
		}
		// record imported function names so a bare name can be used as a value
		for s in imported.symbols {
			g.fn_names[s.name] = true
		}
		// merge debug info, rebasing offsets into this object's code space
		for l in imported.lines {
			g.lines << obj.LineInfo{ off: u32(code_off) + l.off, line: l.line }
		}
		// merge debug locals: module-internal function names get the same
		// prefix as their symbols so the debugger can resolve them
		for l in imported.locals {
			g.dbg_locals << obj.DbgLocal{ fn: prefix + l.fn, name: l.name, slot: l.slot }
		}
	}
	for fd in prog.fns {
		g.fn_names[fd.name] = true
	}
	for fd in prog.fns {
		g.captures = []string{} // top-level functions capture nothing
		g.gen_fn(fd)!
	}
	return obj.Obj{
		symbols: g.symbols
		strings: g.strings
		code:    g.code
		relocs:  g.relocs
		lines:   g.lines
		locals:  g.dbg_locals
	}
}

fn (mut g Gen) gen_fn(fd FnDecl) ! {
	// methods compile to functions named `Type.method`; the receiver is the
	// implicit first argument, so `p.dist(x)` becomes `call Point.dist p, x`
	sym := if fd.recv_type.len > 0 { '${fd.recv_type}.${fd.name}' } else { fd.name }
	g.cur_fn = sym
	g.symbols << obj.Symbol{ name: sym, entry: g.code.len }
	g.lines << obj.LineInfo{ off: u32(g.code.len), line: fd.line }
	g.locals.clear()
	g.types.clear()
	g.local_cnt = 0
	// closure captures occupy the leading local slots (filled by the caller's
	// op_call_closure), then the receiver (methods), then the parameters
	g.argc = fd.params.len + g.captures.len + if fd.recv_type.len > 0 { 1 } else { 0 }
	mut next := 0
	if g.captures.len > 0 {
		for i, c in g.captures {
			g.locals[c] = i
		}
		next = g.captures.len
	} else if fd.recv_type.len > 0 {
		g.locals[fd.recv_name] = 0
		g.types[fd.recv_name] = fd.recv_type
		next = 1
	}
	// a variadic parameter does not occupy an argument slot; it gets a fresh
	// local that the prologue fills with the collected vararg array
	if fd.variadic {
		g.argc--
	}
	for i, p in fd.params {
		if fd.variadic && i == fd.params.len - 1 {
			continue
		}
		g.locals[p] = i + next
	}
	g.local_cnt = g.argc
	if fd.variadic {
		vidx := g.local_cnt
		g.local_cnt++
		g.locals[fd.params[fd.params.len - 1]] = vidx
	}
	// `enter n` reserves the non-parameter locals; n is patched once the body
	// has been scanned.
	g.code << op_enter
	g.enter_off = u32(g.code.len)
	g.code << obj.encode_i64(0)
	// default parameter values: if the caller passed fewer args than this
	// param's slot, evaluate the default and store it
	for i, p in fd.params {
		if fd.variadic && i == fd.params.len - 1 {
			continue
		}
		if i >= fd.has_defs.len || !fd.has_defs[i] {
			continue
		}
		_ = p
		slot := i + next
		skip_l := g.new_label()
		g.code << op_argc
		g.code << op_push_i
		g.code << obj.encode_i64(i64(slot))
		g.code << op_le
		g.code << op_jz
		g.code << obj.encode_i64(0)
		g.fixups << Fixup{ name: skip_l, off: u32(g.code.len) - 8 }
		g.gen_expr(fd.defaults[i])!
		g.emit_store(slot)
		g.emit_label(skip_l)
	}
	// variadic collection: build an array from args[argc..actual-1]
	if fd.variadic {
		vidx := g.locals[fd.params[fd.params.len - 1]] or {
			return error('internal: variadic param missing')
		}
		g.code << op_varargs
		g.code << obj.encode_i64(i64(g.argc))
		g.code << obj.encode_i64(i64(vidx))
	}
	// one-pass defer handling: collect every `defer` statement in the body first
	// (so all returns can be redirected to the deferred-cleanup block), then
	// reserve a hidden slot to hold the return value across that block.
	g.defers = []Stmt{}
	g.has_defers = false
	g.defer_value_seen = false
	g.collect_defers(fd.body, mut g.defers)
	if g.defers.len > 0 {
		g.has_defers = true
		g.defer_ret_slot = g.local_cnt
		g.local_cnt++
	}
	g.cur_defer_label = g.new_label()
	for st in fd.body {
		g.gen_stmt(st)!
	}

	if g.has_defers {
		g.code << op_jmp
		g.code << obj.encode_i64(0)
		g.fixups << Fixup{ name: g.cur_defer_label, off: u32(g.code.len) - 8 }
	} else {
		g.code << op_ret // trailing return for fall-through
	}
	// emit the deferred-cleanup block (LIFO) then the real return here, so a
	// `return` in the body jumps into this block and lands back on the return
	if g.has_defers {
		g.emit_label(g.cur_defer_label)
		for i := g.defers.len - 1; i >= 0; i-- {
			g.gen_stmt(g.defers[i])!
		}
		if g.defer_value_seen {
			// restore the saved return value and return it
			g.emit_load(g.defer_ret_slot)
			g.code << op_retv
		} else {
			g.code << op_ret
		}
	}
	// reserve all local slots: the callee may be called with fewer arguments
	// than declared (default parameters) or more (variadic), so the frame must
	// always cover slots 0..local_cnt-1
	obj.patch_i64(mut g.code, g.enter_off, i64(g.local_cnt))
	// resolve intra-function jump targets. Targets are encoded PC-relative
	// (delta from the end of the 8-byte operand), so bytecode stays
	// position-independent when module objects are merged or linked.
	for f in g.fixups {
		target := g.labels[f.name] or {
			return error('internal error: unresolved label ${f.name} in fn ${fd.name}')
		}
		obj.patch_i64(mut g.code, f.off, i64(target - (int(f.off) + 8)))
	}
	g.fixups.clear()
	g.labels.clear()
	g.defers = []Stmt{} // reset for the next (possibly enclosing) function
	g.has_defers = false
	// snapshot the live locals as debug info for the debugger: name -> slot
	for name, slot in g.locals {
		g.dbg_locals << obj.DbgLocal{ fn: sym, name: name, slot: slot }
	}
	g.cur_fn = ''
}

fn (mut g Gen) gen_stmt(st Stmt) ! {
	g.lines << obj.LineInfo{ off: u32(g.code.len), line: st.line }
	match st.kind {
		.expr_stmt {
			g.gen_expr(st.expr)!
			// print/println already consume their value; everything else
			// leaves one on the stack that must be discarded
			if st.expr.kind == .call && (st.expr.name == 'print' || st.expr.name == 'println') {
				// nothing to discard
			} else {
				g.code << op_pop
			}
		}
		.let_stmt {
			g.gen_expr(st.expr)!
			idx := g.local_cnt
			g.local_cnt++
			g.locals[st.target] = idx
			g.types[st.target] = g.expr_type(st.expr)
			g.code << op_store
			g.code << obj.encode_i64(i64(idx))
		}
		.destruct_stmt {
			// let { a, b } = e  →  tmp := e; a := tmp.a; b := tmp.b
			// let [a, b] = e   →  tmp := e; a := tmp[0]; b := tmp[1]
			tmp_idx := g.new_local()
			g.gen_expr(st.expr)!
			g.emit_store(tmp_idx)
			for i, name in st.destruct_targets {
				g.emit_load(tmp_idx)
				if st.destruct_field {
					g.emit_field_name(name)
					g.code << op_sget
				} else {
					g.code << op_push_i
					g.code << obj.encode_i64(i64(i))
					g.code << op_aget
				}
				idx := g.new_local()
				g.locals[name] = idx
				g.types.delete(name)
				g.emit_store(idx)
			}
		}
		.assign_stmt {
			idx := g.locals[st.target] or {
				return error('unknown variable "${st.target}" at line ${st.line}')
			}
			g.gen_expr(st.expr)!
			g.types[st.target] = g.expr_type(st.expr)
			g.code << op_store
			g.code << obj.encode_i64(i64(idx))
		}
		.index_assign {
			// if the index is a string literal, use struct field set (map style)
			if st.idx.kind == .str_lit {
				g.gen_expr(st.base)!
				g.gen_expr(st.expr)!
				g.emit_field_name(st.idx.str_v)
				g.code << op_sset
			} else {
				g.gen_expr(st.base)!
				g.gen_expr(st.idx)!
				g.gen_expr(st.expr)!
				g.code << op_aset
			}
		}
		.field_assign {
			// a.b = v  →  a, v, "b"  sset   (field name on top of the stack)
			g.gen_expr(st.base)!
			g.gen_expr(st.expr)!
			g.emit_field_name(st.target)
			g.code << op_sset
		}
		.if_stmt {
			else_l := g.new_label()
			end_l := g.new_label()
			g.gen_expr(st.cond)!
			g.code << op_jz
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: else_l, off: u32(g.code.len) - 8 }
			for s in st.body {
				g.gen_stmt(s)!
			}
			g.code << op_jmp
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: end_l, off: u32(g.code.len) - 8 }
			g.emit_label(else_l)
			for s in st.els {
				g.gen_stmt(s)!
			}
			g.emit_label(end_l)
		}
		.match_stmt {
			// match x { v1 {..} v2 {..} else {..} }  →  subject := x; a chain of
			// equality tests jumping to the matching arm; else falls through.
			subj_idx := g.new_local()
			end_l := g.new_label()
			g.gen_expr(st.expr)!
			g.emit_store(subj_idx)
			for i, arm in st.arms {
				next_l := g.new_label()
				if arm.is_range {
					// range arm: `lo..hi {}` matches when lo <= subj <= hi.
					// Short-circuit: if subj < lo, jump to next; if subj > hi, too.
					g.emit_load(subj_idx)
					g.gen_expr(arm.val)!
					g.code << op_lt
					g.code << op_jnz
					g.code << obj.encode_i64(0)
					g.fixups << Fixup{ name: next_l, off: u32(g.code.len) - 8 }
					g.emit_load(subj_idx)
					g.gen_expr(arm.range_end)!
					g.code << op_gt
					g.code << op_jnz
					g.code << obj.encode_i64(0)
					g.fixups << Fixup{ name: next_l, off: u32(g.code.len) - 8 }
				} else {
					g.emit_load(subj_idx)
					g.gen_expr(arm.val)!
					g.code << op_eq
					g.code << op_jz
					g.code << obj.encode_i64(0)
					g.fixups << Fixup{ name: next_l, off: u32(g.code.len) - 8 }
				}
				for s in arm.body {
					g.gen_stmt(s)!
				}
				g.code << op_jmp
				g.code << obj.encode_i64(0)
				g.fixups << Fixup{ name: end_l, off: u32(g.code.len) - 8 }
				g.emit_label(next_l)
				if i == st.arms.len - 1 && !st.has_else {
					// no else: fall through to the end label
					g.emit_label(end_l)
				}
			}
			if st.has_else {
				for s in st.els_body {
					g.gen_stmt(s)!
				}
				g.emit_label(end_l)
			}
		}
		.while_stmt {
			loop_l := g.new_label()
			end_l := g.new_label()
			g.emit_label(loop_l)
			g.gen_expr(st.cond)!
			g.code << op_jz
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: end_l, off: u32(g.code.len) - 8 }
			g.loops << LoopCtx{ break_l: end_l, continue_l: loop_l }
			for s in st.body {
				g.gen_stmt(s)!
			}
			g.loops.delete_last()
			g.code << op_jmp
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: loop_l, off: u32(g.code.len) - 8 }
			g.emit_label(end_l)
		}
		.for_range_stmt {
			// for i in a..b / for i in a...b  →  i := a; while i <(<=) b { body; i++ }
			var_idx := g.new_local()
			bound_idx := g.new_local()
			loop_l := g.new_label()
			inc_l := g.new_label()
			end_l := g.new_label()
			g.gen_expr(st.expr)!
			g.gen_expr(st.cond)!
			g.emit_store(bound_idx)
			g.emit_store(var_idx)
			g.emit_label(loop_l)
			g.emit_load(var_idx)
			g.emit_load(bound_idx)
			g.code << if st.inclusive { op_le } else { op_lt }
			g.code << op_jz
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: end_l, off: u32(g.code.len) - 8 }
			g.loops << LoopCtx{ break_l: end_l, continue_l: inc_l }
			prev := g.locals[st.target] or { -1 }
			prev_t := g.types[st.target] or { '' }
			g.locals[st.target] = var_idx
			g.types.delete(st.target)
			for s in st.body {
				g.gen_stmt(s)!
			}
			if prev >= 0 {
				g.locals[st.target] = prev
			} else {
				g.locals.delete(st.target)
			}
			if prev_t.len > 0 {
				g.types[st.target] = prev_t
			}
			g.loops.delete_last()
			g.emit_label(inc_l)
			g.emit_load(var_idx)
			g.code << op_push_i
			g.code << obj.encode_i64(1)
			g.code << op_add
			g.emit_store(var_idx)
			g.code << op_jmp
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: loop_l, off: u32(g.code.len) - 8 }
			g.emit_label(end_l)
		}
		.for_in_stmt {
			// for x in EnumType { ... }  →  iterate over enum variants as integers
			if st.expr.kind == .ident && st.expr.name in g.enums {
				g.gen_for_enum(st.target, st.expr.name, st.body, st.line)!
				return
			}
			// for x in arr  →  idx := 0; while idx < len(arr) { x := arr[idx]; body; idx++ }
			arr_idx := g.new_local()
			idx_idx := g.new_local()
			elem_idx := g.new_local()
			loop_l := g.new_label()
			inc_l := g.new_label()
			end_l := g.new_label()
			g.gen_expr(st.expr)!
			g.emit_store(arr_idx)
			g.code << op_push_i
			g.code << obj.encode_i64(0)
			g.emit_store(idx_idx)
			g.emit_label(loop_l)
			g.emit_load(idx_idx)
			g.emit_load(arr_idx)
			g.code << op_alen
			g.code << op_lt
			g.code << op_jz
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: end_l, off: u32(g.code.len) - 8 }
			g.loops << LoopCtx{ break_l: end_l, continue_l: inc_l }
			g.emit_load(arr_idx)
			g.emit_load(idx_idx)
			g.code << op_aget
			g.emit_store(elem_idx)
			prev := g.locals[st.target] or { -1 }
			prev_t := g.types[st.target] or { '' }
			g.locals[st.target] = elem_idx
			g.types.delete(st.target)
			// bind the index variable if present (for i, v in arr)
			prev_idx := if st.idx_target.len > 0 { g.locals[st.idx_target] or { -1 } } else { -1 }
			prev_idx_t := if st.idx_target.len > 0 { g.types[st.idx_target] or { '' } } else { '' }
			if st.idx_target.len > 0 {
				g.locals[st.idx_target] = idx_idx
				g.types.delete(st.idx_target)
			}
			for s in st.body {
				g.gen_stmt(s)!
			}
			if st.idx_target.len > 0 {
				if prev_idx >= 0 {
					g.locals[st.idx_target] = prev_idx
				} else {
					g.locals.delete(st.idx_target)
				}
				if prev_idx_t.len > 0 {
					g.types[st.idx_target] = prev_idx_t
				}
			}
			if prev >= 0 {
				g.locals[st.target] = prev
			} else {
				g.locals.delete(st.target)
			}
			if prev_t.len > 0 {
				g.types[st.target] = prev_t
			}
			g.loops.delete_last()
			g.emit_label(inc_l)
			g.emit_load(idx_idx)
			g.code << op_push_i
			g.code << obj.encode_i64(1)
			g.code << op_add
			g.emit_store(idx_idx)
			g.code << op_jmp
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: loop_l, off: u32(g.code.len) - 8 }
			g.emit_label(end_l)
		}
		.ret_stmt {
			if g.has_defers {
				// save any return value in the hidden slot, jump into the
				// deferred-cleanup block, which restores and returns it
				if st.has_val {
					g.defer_value_seen = true
					g.gen_expr(st.expr)!
					g.emit_store(g.defer_ret_slot)
				} else {
					g.code << op_push_i
					g.code << obj.encode_i64(0)
					g.emit_store(g.defer_ret_slot)
				}
				g.code << op_jmp
				g.code << obj.encode_i64(0)
				g.fixups << Fixup{ name: g.cur_defer_label, off: u32(g.code.len) - 8 }
			} else {
				if st.has_val {
					g.gen_expr(st.expr)!
					g.code << op_retv
				} else {
					g.code << op_ret
				}
			}
		}
		.defer_stmt {
			// collected in gen_fn's pass and emitted in the cleanup block;
			// nothing to place at the declaration site
		}
		.assert_stmt {
			g.gen_expr(st.expr)!
			g.code << op_assert
		}
		.break_stmt {
			if g.loops.len == 0 {
				return error('break outside of a loop (line ${st.line})')
			}
			ctx := g.loops[g.loops.len - 1]
			g.code << op_jmp
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: ctx.break_l, off: u32(g.code.len) - 8 }
		}
		.continue_stmt {
			if g.loops.len == 0 {
				return error('continue outside of a loop (line ${st.line})')
			}
			ctx := g.loops[g.loops.len - 1]
			g.code << op_jmp
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: ctx.continue_l, off: u32(g.code.len) - 8 }
		}
		.throw_stmt {
			g.gen_expr(st.expr)!
			g.code << op_throw
		}
		.try_stmt {
			catch_l := g.new_label()
			end_l := g.new_label()
			err_idx := g.new_local()
			g.code << op_try
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: catch_l, off: u32(g.code.len) - 8 }
			for s in st.body {
				g.gen_stmt(s)!
			}
			g.code << op_catch_done
			g.code << op_jmp
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: end_l, off: u32(g.code.len) - 8 }
			g.emit_label(catch_l)
			g.code << op_store
			g.code << obj.encode_i64(i64(err_idx))
			prev := g.locals[st.target] or { -1 }
			prev_t := g.types[st.target] or { '' }
			g.locals[st.target] = err_idx
			g.types.delete(st.target)
			for s in st.els {
				g.gen_stmt(s)!
			}
			if prev >= 0 {
				g.locals[st.target] = prev
			} else {
				g.locals.delete(st.target)
			}
			if prev_t.len > 0 {
				g.types[st.target] = prev_t
			}
			g.emit_label(end_l)
		}
	}
}

fn (mut g Gen) gen_expr(e Expr) ! {
	match e.kind {
		.int_lit {
			g.code << op_push_i
			g.code << obj.encode_i64(e.int_v)
		}
		.float_lit {
			g.code << op_push_f
			g.code << obj.encode_f64(e.float_v)
		}
		.str_lit {
			// the index is a placeholder; the linker rebases it via a string
			// relocation so multi-file links keep working
			g.code << op_push_s
			g.code << obj.encode_i64(0)
			g.relocs << obj.Reloc{ offset: u32(g.code.len) - 8, name: e.str_v, kind: 1 }
		}
		.array_lit {
			for el in e.elems {
				g.gen_expr(el)!
			}
			g.code << op_mkarray
			g.code << obj.encode_i64(i64(e.elems.len))
		}
		.struct_lit {
			// typed literals validate their fields against the declaration
			// (an undeclared type name is allowed — it may live in another
			// file, where the same validation applies)
			if e.name.len > 0 && e.name in g.structs {
				decl_fields := g.structs[e.name]
				mut seen := map[string]bool{}
				for f in e.fields {
					if f.name !in decl_fields {
						return error('unknown field "${f.name}" for struct ${e.name} (line ${e.line})')
					}
					if f.name in seen {
						return error('duplicate field "${f.name}" in struct literal (line ${e.line})')
					}
					seen[f.name] = true
				}
			}
			// for each field: push the name string then the value; mkstruct n
			// pops the (name, value) pairs and builds the record
			for f in e.fields {
				g.emit_field_name(f.name)
				g.gen_expr(f.val)!
			}
			g.code << op_mkstruct
			g.code << obj.encode_i64(i64(e.fields.len))
		}
		.field {
			// check if it's an enum variant (e.g., Color.red)
			if e.left.kind == .ident {
				key := '${e.left.name}.${e.name}'
				if key in g.enum_vals {
					g.code << op_push_i
					g.code << obj.encode_i64(i64(g.enum_vals[key]))
					return
				}
			}
			g.gen_expr(*e.left)!
			g.emit_field_name(e.name)
			g.code << op_sget
		}
	.method_call {
		// module call: os.exists(x) — the receiver is an imported module name
		if e.left.kind == .ident && e.left.name in g.modules {
			for a in e.args {
				g.gen_expr(a)!
			}
			g.code << op_call
			g.code << obj.encode_i64(0) // placeholder — patched by the linker
			g.relocs << obj.Reloc{ offset: u32(g.code.len) - 8, name: '${e.left.name}.${e.name}', kind: 0 }
			g.code << obj.encode_i64(i64(e.args.len))
			return
		}
		// p.dist(x)  →  call <Type>.dist  p, x
		recv_t := g.method_receiver_type(e)
		// string methods: s.len(), s.to_upper(), s.contains(x), ... —
		// the receiver type is known when it is a literal or a local that
		// was assigned a string literal
		if recv_t == 'string' || e.left.kind == .str_lit {
				g.gen_expr(*e.left)!
				for a in e.args {
					g.gen_expr(a)!
				}
				g.code << op_str_method
				g.code << obj.encode_i64(0) // name placeholder — rebased by the linker
				g.relocs << obj.Reloc{ offset: u32(g.code.len) - 8, name: e.name, kind: 1 }
				g.code << obj.encode_i64(i64(e.args.len))
				return
			}
			// built-in: enum.to_string() generates a match on the integer value
			if e.name == 'to_string' && recv_t in g.enums && e.args.len == 0 {
				g.gen_enum_to_string(recv_t, *e.left, e.line)!
				return
			}
			// built-in: enum.count() returns the number of variants
			if e.name == 'count' && recv_t in g.enums && e.args.len == 0 {
				g.gen_expr(*e.left)!
				g.code << op_pop
				variants := g.enums[recv_t]
				g.code << op_push_i
				g.code << obj.encode_i64(i64(variants.len))
				return
			}
			g.gen_expr(*e.left)!
			for a in e.args {
				g.gen_expr(a)!
			}
			// if receiver type is known, emit a static method call
			if recv_t.len > 0 {
				g.code << op_call
				g.code << obj.encode_i64(0) // placeholder — patched by the linker
				g.relocs << obj.Reloc{ offset: u32(g.code.len) - 8, name: '${recv_t}.${e.name}', kind: 0 }
				g.code << obj.encode_i64(i64(e.args.len + 1)) // receiver + args
		} else {
			// unknown type: treat as closure call on a struct field
			g.emit_field_name(e.name)
			g.code << op_sget
			for a in e.args {
				g.gen_expr(a)!
			}
			g.code << op_call_closure
			g.code << obj.encode_i64(i64(e.args.len))
		}
		return
	}
		.index {
			// if the index is a string literal, use struct field access (map style)
			if e.right.kind == .str_lit {
				g.gen_expr(*e.left)!
				g.emit_field_name(e.right.str_v)
				g.code << op_sget
			} else {
				g.gen_expr(*e.left)!
				g.gen_expr(*e.right)!
				g.code << op_aget
			}
		}
		.slice {
			// arr[start..end]  →  push value, start, end; slice
			g.gen_expr(*e.left)!
			g.gen_expr(*e.right)!
			g.gen_expr(*e.extra)!
			g.code << op_slice
		}
		.anon_fn {
			g.lam_counter++
			name := '__lam_${g.lam_counter}'
			// find the enclosing locals the body references (its free
			// variables); they become this closure's captures
			caps := g.scan_captures(e.fn_body, e.fparams)
			// jump over the lambda body so callers don't fall through
			g.code << op_jmp
			g.code << obj.encode_i64(0)
			skip_fix_off := u32(g.code.len) - 8
			fd := FnDecl{
				name: name
				params: e.fparams
				defaults: e.fdefaults
				has_defs: e.fhas_defs
				variadic: e.fvariadic
				body: e.fn_body
				line: e.line
			}
			// Save enclosing fixup/label/locals/type state; gen_fn clears them.
			// enter_off and argc are also per-function, so they must be restored
			// or the enclosing function's `enter n` patch is lost (locals would
			// then collide with the stack top).
			saved_fixups := g.fixups.clone()
			saved_labels := g.labels.clone()
			saved_locals := g.locals.clone()
			saved_types := g.types.clone()
			saved_local_cnt := g.local_cnt
			saved_enter_off := g.enter_off
			saved_argc := g.argc
			saved_captures := g.captures
			g.labels.clear()
			g.fixups = []Fixup{}
			g.captures = caps
			g.gen_fn(fd)!
			// Restore the enclosing state.
			g.fixups = saved_fixups
			g.labels = saved_labels.clone()
			g.locals = saved_locals.clone()
			g.types = saved_types.clone()
			g.local_cnt = saved_local_cnt
			g.enter_off = saved_enter_off
			g.argc = saved_argc
			g.captures = saved_captures
			// Patch the skip jump to land at the closure opcode we emit next
			// (PC-relative, like all other jump targets).
			obj.patch_i64(mut g.code, skip_fix_off, i64(g.code.len - (int(skip_fix_off) + 8)))
			// capture the enclosing locals' current values (capture by value)
			for cname in caps {
				g.emit_load(g.locals[cname])
			}
			g.code << op_closure
			g.code << obj.encode_i64(0)
			g.relocs << obj.Reloc{ offset: u32(g.code.len) - 8, name: name, kind: 0 }
			g.code << obj.encode_i64(i64(caps.len))
		}
		.bool_lit {
			g.code << op_push_i
			g.code << obj.encode_i64(e.int_v)
		}
		.none_lit {
			g.code << op_push_none
		}
		.ident {
			// check if it's a constant — emit the right opcode for its literal kind
			if e.name in g.consts {
				cv := g.consts[e.name] or { panic('codegen: constant "${e.name}" missing') }
				match cv.kind {
					.int_lit, .bool_lit {
						g.code << op_push_i
						g.code << obj.encode_i64(cv.int_v)
					}
					.str_lit {
						g.code << op_push_s
						g.code << obj.encode_i64(0)
						g.relocs << obj.Reloc{ offset: u32(g.code.len) - 8, name: cv.str_v, kind: 1 }
					}
					.float_lit {
						g.code << op_push_f
						g.code << obj.encode_f64(cv.float_v)
					}
					else {
						g.code << op_push_i
						g.code << obj.encode_i64(0)
					}
				}
			} else if e.name in g.enum_vals {
				// check if it's an enum variant (e.g., Color.red)
				g.code << op_push_i
				g.code << obj.encode_i64(i64(g.enum_vals[e.name]))
			} else if e.name in g.locals {
				idx := g.locals[e.name]
				g.code << op_load
				g.code << obj.encode_i64(i64(idx))
			} else if e.name in g.fn_names {
				// a bare top-level function name used as a value (e.g. the first
				// argument of `spawn`) — emit a zero-capture closure whose entry
				// is resolved by the linker.
				g.code << op_closure
				g.code << obj.encode_i64(0)
				g.relocs << obj.Reloc{ offset: u32(g.code.len) - 8, name: e.name, kind: 0 }
				g.code << obj.encode_i64(0) // no captured locals
			} else {
				return error('unknown variable "${e.name}" at line ${e.line}')
			}
		}
		.unary {
			// constant-fold unary ops on literals: -5, -2.5, not true, ~7
			if e.right.kind == .int_lit && (e.op == .minus || e.op == .tilde) {
				v := e.right.int_v
				res := if e.op == .minus { -v } else { ~v }
				g.code << op_push_i
				g.code << obj.encode_i64(res)
				return
			}
			if e.right.kind == .float_lit && e.op == .minus {
				g.code << op_push_f
				g.code << obj.encode_f64(-e.right.float_v)
				return
			}
			if e.right.kind == .bool_lit && e.op == .kw_not {
				g.code << op_push_i
				g.code << obj.encode_i64(if e.right.int_v == 0 { 1 } else { 0 })
				return
			}
			g.gen_expr(*e.right)!
			match e.op {
				.kw_not { g.code << op_not }
				.tilde { g.code << op_not_b }
				else { g.code << op_neg }
			}
		}
		.binary {
			g.gen_binary(e)!
		}
		.call {
			g.gen_call(e)!
		}
	}
}

fn (mut g Gen) gen_call(e Expr) ! {
	if e.name == 'print' || e.name == 'println' {
		if e.args.len != 1 {
			return error('${e.name}() takes exactly one argument (line ${e.line})')
		}
		g.gen_expr(e.args[0])!
		g.code << if e.name == 'print' { op_print } else { op_println }
		return
	}
	if e.name == 'len' {
		if e.args.len != 1 {
			return error('len() takes exactly one argument (line ${e.line})')
		}
		g.gen_expr(e.args[0])!
		g.code << op_alen
		return
	}
	if e.name == 'push' {
		if e.args.len != 2 {
			return error('push() takes exactly two arguments (line ${e.line})')
		}
		g.gen_expr(e.args[0])!
		g.gen_expr(e.args[1])!
		g.code << op_apush
		return
	}
	if e.name == 'has' {
		if e.args.len != 2 {
			return error('has() takes exactly two arguments (line ${e.line})')
		}
		g.gen_expr(e.args[0])!
		g.gen_expr(e.args[1])!
		g.code << op_shas
		return
	}
	if e.name == 'delete' {
		if e.args.len != 2 {
			return error('delete() takes exactly two arguments (line ${e.line})')
		}
		g.gen_expr(e.args[0])!
		g.gen_expr(e.args[1])!
		g.code << op_sdel
		return
	}
	if e.name == 'keys' {
		if e.args.len != 1 {
			return error('keys() takes exactly one argument (line ${e.line})')
		}
		g.gen_expr(e.args[0])!
		g.code << op_skeys
		return
	}
	// closure call: ident(args) where ident is a local holding a closure.
	// The local's value is pushed as the call sequence's first slot;
	// op_call_closure consumes it along with the args, leaving only the
	// result on the stack.
	if e.name in g.locals {
		g.gen_expr(Expr{ kind: .ident, name: e.name, line: e.line })!
		for a in e.args {
			g.gen_expr(a)!
		}
		g.code << op_call_closure
		g.code << obj.encode_i64(i64(e.args.len))
		return
	}
	// host builtins (file I/O, OS, math, collections) go through op_native
	bid, bargc := builtin_spec(e.name)
	if bid >= 0 {
		// spawn takes a variable number of arguments (the function followed by
		// its call arguments), so emit the real argc rather than the spec's
		if e.name == 'spawn' {
			if e.args.len < 1 {
				return error('spawn expects a function plus zero or more arguments (line ${e.line})')
			}
			for a in e.args {
				g.gen_expr(a)!
			}
			g.code << op_native
			g.code << obj.encode_i64(i64(bid))
			g.code << obj.encode_i64(i64(e.args.len))
			return
		}
		if e.args.len != bargc {
			return error('${e.name}() takes exactly ${bargc} argument(s) (line ${e.line})')
		}
		for a in e.args {
			g.gen_expr(a)!
		}
		g.code << op_native
		g.code << obj.encode_i64(i64(bid))
		g.code << obj.encode_i64(i64(bargc))
		return
	}
	for a in e.args {
		g.gen_expr(a)!
	}
	g.code << op_call
	g.code << obj.encode_i64(0) // placeholder — patched by the linker
	g.relocs << obj.Reloc{ offset: u32(g.code.len) - 8, name: e.name, kind: 0 }
	g.code << obj.encode_i64(i64(e.args.len)) // argc
}

// builtin_spec maps a builtin function name to its (native id, arg count).
// A negative id means the name is not a builtin (it is a user function).
fn builtin_spec(name string) (int, int) {
	return match name {
		'abs' { native_abs, 1 }
		'min' { native_min, 2 }
		'max' { native_max, 2 }
		'pow' { native_pow, 2 }
		'sqrt' { native_sqrt, 1 }
		'floor' { native_floor, 1 }
		'ceil' { native_ceil, 1 }
		'round' { native_round, 1 }
		'rand' { native_rand, 0 }
		'rand_int' { native_rand_int, 1 }
		'int' { native_int, 1 }
		'str' { native_str, 1 }
		'float' { native_float, 1 }
		'type' { native_type, 1 }
		'split' { native_split, 2 }
		'join' { native_join, 2 }
		'contains' { native_contains, 2 }
		'starts_with' { native_starts_with, 2 }
		'ends_with' { native_ends_with, 2 }
		'trim' { native_trim, 1 }
		'lower' { native_lower, 1 }
		'upper' { native_upper, 1 }
		'pop' { native_pop, 1 }
		'insert' { native_insert, 3 }
		'remove' { native_remove, 2 }
		'sort' { native_sort, 1 }
		'clone' { native_clone, 1 }
		'reverse' { native_reverse, 1 }
		'index_of' { native_index_of, 2 }
		'args' { native_args, 0 }
		'getenv' { native_getenv, 1 }
		'setenv' { native_setenv, 2 }
		'exit' { native_exit, 1 }
		'time' { native_time, 0 }
		'sleep' { native_sleep, 1 }
		'read_file' { native_read_file, 1 }
		'write_file' { native_write_file, 2 }
		'eprint' { native_eprint, 1 }
		// build-module builtins (.vrmm) — see vm/native.v
		'build_compile' { native_build_compile, 2 }
		'build_assemble' { native_build_assemble, 2 }
		'build_link' { native_build_link, 2 }
		'build_run' { native_build_run, 1 }
		'build_test' { native_build_test, 1 }
		'build_bench' { native_build_bench, 2 }
		'build_clean' { native_build_clean, 0 }
		'build_exec' { native_build_exec, 1 }
		'build_exec_status' { native_build_exec_status, 1 }
		'build_exists' { native_build_exists, 1 }
		'build_mkdir' { native_build_mkdir, 1 }
		'build_rm' { native_build_rm, 1 }
		'build_copy' { native_build_copy, 2 }
		'build_glob' { native_build_glob, 1 }
		'build_ls' { native_build_ls, 1 }
		'build_base' { native_build_base, 1 }
		'build_dir' { native_build_dir, 1 }
		'build_join' { native_build_join, 2 }
		'build_root' { native_build_root, 0 }
		// stdlib: JSON + string formatting
		'json_encode' { native_json_encode, 1 }
		'json_decode' { native_json_decode, 1 }
		'format' { native_format, 2 }
		'replace' { native_replace, 3 }
		'split_lines' { native_split_lines, 1 }
		'pad' { native_pad, 2 }
		'pad_left' { native_pad_left, 2 }
		'repeat' { native_repeat, 2 }
		// string builder
		'sb_new' { native_sb_new, 0 }
		'sb_add' { native_sb_add, 2 }
		'sb_str' { native_sb_str, 1 }
		'sb_len' { native_sb_len, 1 }
		// concurrency
		'spawn' { native_spawn, 1 }
		'spawn_join' { native_spawn_join, 1 }
		// interactive input
		'read_line' { native_read_line, 0 }
		'input' { native_input, 1 }
		// getopt-style flag parsing
		'flag_val' { native_flag_val, 1 }
		'flag_has' { native_flag_has, 1 }
		'flag_positional' { native_flag_positional, 0 }
		// structured reflection + sequence helper
		'type_info' { native_type_info, 1 }
		'range' { native_range, 2 }
		'build_is_dir' { native_build_is_dir, 1 }
		'cwd' { native_cwd, 0 }
		'json_pretty' { native_json_pretty, 1 }
		// HTTP client
		'http_get' { native_http_get, 1 }
		'http_post' { native_http_post, 2 }
		// date/time
		'now' { native_now, 0 }
		'time_ms' { native_time_ms, 0 }
		'format_time' { native_format_time, 2 }
		'parse_time' { native_parse_time, 1 }
		'weekday' { native_weekday, 1 }
		// regex
		'regex_match' { native_regex_match, 2 }
		'regex_find_all' { native_regex_find_all, 2 }
		'regex_replace' { native_regex_replace, 3 }
		'regex_split' { native_regex_split, 2 }
		// crypto/encoding
		'base64_encode' { native_base64_encode, 1 }
		'base64_decode' { native_base64_decode, 1 }
		'sha256' { native_sha256, 1 }
		'md5' { native_md5, 1 }
		'csv_parse' { native_csv_parse, 1 }
		// extended HTTP + path/process helpers
		'http_req' { native_http_req, 5 }
		'path_ext' { native_path_ext, 1 }
		'path_abs' { native_path_abs, 1 }
		'path_rel' { native_path_rel, 2 }
		'exec_full' { native_exec_full, 1 }
		else { -1, 0 }
	}
}

// fold_binary constant-folds binary expressions whose operands are both
// literals, emitting the precomputed constant. Returns false when the
// expression cannot be folded (leaving it to the runtime). Division/modulo by
// zero and out-of-range shifts are deliberately not folded so the runtime
// still reports them.
fn (mut g Gen) fold_binary(e Expr) bool {
	// integer folding
	if e.left.kind == .int_lit && e.right.kind == .int_lit {
		l := e.left.int_v
		r := e.right.int_v
		mut res := i64(0)
		match e.op {
			.plus { res = l + r }
			.minus { res = l - r }
			.star { res = l * r }
			.slash {
				if r == 0 {
					return false
				}
				res = l / r
			}
			.percent {
				if r == 0 {
					return false
				}
				res = l % r
			}
			.amp { res = l & r }
			.pipe { res = l | r }
			.caret { res = l ^ r }
			.lt_lt {
				if r < 0 || r > 63 {
					return false
				}
				res = l << u32(r)
			}
			.gt_gt {
				if r < 0 || r > 63 {
					return false
				}
				res = l >> u32(r)
			}
			.eq_eq { res = if l == r { 1 } else { 0 } }
			.not_eq { res = if l != r { 1 } else { 0 } }
			.lt { res = if l < r { 1 } else { 0 } }
			.le { res = if l <= r { 1 } else { 0 } }
			.gt { res = if l > r { 1 } else { 0 } }
			.ge { res = if l >= r { 1 } else { 0 } }
			else { return false }
		}
		g.code << op_push_i
		g.code << obj.encode_i64(res)
		return true
	}
	// float folding
	if e.left.kind == .float_lit && e.right.kind == .float_lit {
		l := e.left.float_v
		r := e.right.float_v
		mut res := 0.0
		mut is_bool := false
		mut bres := false
		match e.op {
			.plus { res = l + r }
			.minus { res = l - r }
			.star { res = l * r }
			.slash {
				if r == 0.0 {
					return false
				}
				res = l / r
			}
			.eq_eq { is_bool = true; bres = l == r }
			.not_eq { is_bool = true; bres = l != r }
			.lt { is_bool = true; bres = l < r }
			.le { is_bool = true; bres = l <= r }
			.gt { is_bool = true; bres = l > r }
			.ge { is_bool = true; bres = l >= r }
			else { return false }
		}
		if is_bool {
			g.code << op_push_i
			g.code << obj.encode_i64(if bres { 1 } else { 0 })
		} else {
			g.code << op_push_f
			g.code << obj.encode_f64(res)
		}
		return true
	}
	// string concatenation folding: "a" + "b" → one interned constant.
	// The string is emitted as a relocation so the linker interns it in the
	// final table, exactly like a plain string literal.
	if e.left.kind == .str_lit && e.right.kind == .str_lit && e.op == .plus {
		g.code << op_push_s
		g.code << obj.encode_i64(0) // placeholder — rebased by the linker
		g.relocs << obj.Reloc{ offset: u32(g.code.len) - 8, name: e.left.str_v + e.right.str_v, kind: 1 }
		return true
	}
	// boolean short-circuit folding: only when both sides are bool literals
	if e.left.kind == .bool_lit && e.right.kind == .bool_lit {
		if e.op == .kw_and {
			g.code << op_push_i
			g.code << obj.encode_i64(if e.left.int_v != 0 && e.right.int_v != 0 { 1 } else { 0 })
			return true
		}
		if e.op == .kw_or {
			g.code << op_push_i
			g.code << obj.encode_i64(if e.left.int_v != 0 || e.right.int_v != 0 { 1 } else { 0 })
			return true
		}
	}
	return false
}

fn (mut g Gen) gen_binary(e Expr) ! {
	if g.fold_binary(e) {
		return
	}
	match e.op {
		.kw_and {
			// a and b  →  short-circuit: if !a or !b then 0 else 1
			false_l := g.new_label()
			end_l := g.new_label()
			g.gen_expr(*e.left)!
			g.code << op_jz
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: false_l, off: u32(g.code.len) - 8 }
			g.gen_expr(*e.right)!
			g.code << op_jz
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: false_l, off: u32(g.code.len) - 8 }
			g.code << op_push_i
			g.code << obj.encode_i64(1)
			g.code << op_jmp
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: end_l, off: u32(g.code.len) - 8 }
			g.emit_label(false_l)
			g.code << op_push_i
			g.code << obj.encode_i64(0)
			g.emit_label(end_l)
		}
		.kw_or {
			// a or b  →  short-circuit: if a or b then 1 else 0
			true_l := g.new_label()
			end_l := g.new_label()
			g.gen_expr(*e.left)!
			g.code << op_jnz
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: true_l, off: u32(g.code.len) - 8 }
			g.gen_expr(*e.right)!
			g.code << op_jnz
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: true_l, off: u32(g.code.len) - 8 }
			g.code << op_push_i
			g.code << obj.encode_i64(0)
			g.code << op_jmp
			g.code << obj.encode_i64(0)
			g.fixups << Fixup{ name: end_l, off: u32(g.code.len) - 8 }
			g.emit_label(true_l)
			g.code << op_push_i
			g.code << obj.encode_i64(1)
			g.emit_label(end_l)
		}
		else {
			g.gen_expr(*e.left)!
			g.gen_expr(*e.right)!
			op := match e.op {
				.plus { op_add }
				.minus { op_sub }
				.star { op_mul }
				.slash { op_div }
				.percent { op_mod }
				.eq_eq { op_eq }
				.not_eq { op_ne }
				.lt { op_lt }
				.le { op_le }
				.gt { op_gt }
				.ge { op_ge }
				.kw_in { op_in }
				.amp { op_and_b }
				.pipe { op_or_b }
				.caret { op_xor }
				.lt_lt { op_shl }
				.gt_gt { op_shr }
				else {
					return error('unsupported binary operator at line ${e.line}')
				}
			}
			g.code << op
		}
	}
}

// expr_type returns the declared struct type of an expression when it is
// statically knowable: a typed literal `Point{...}`, a copy of a typed
// variable, or an enum variant `Enum.variant`. Everything else has no
// known type ('').
fn (mut g Gen) expr_type(e Expr) string {
	if e.kind == .str_lit {
		return 'string'
	}
	if e.kind == .struct_lit {
		return e.name
	}
	if e.kind == .ident {
		return g.types[e.name] or { '' }
	}
	// enum variant: Color.red  →  type is "Color"
	if e.kind == .field && e.left.kind == .ident {
		key := '${e.left.name}.${e.name}'
		if key in g.enum_vals {
			return e.left.name
		}
	}
	// slicing or indexing a known string yields a string
	if (e.kind == .slice || e.kind == .index) && g.expr_type(*e.left) == 'string' {
		return 'string'
	}
	// string concatenation: "a" + "b" (or anything + a string literal)
	if e.kind == .binary && e.op == .plus && (e.left.kind == .str_lit || e.right.kind == .str_lit) {
		return 'string'
	}
	// string-producing builtins typed as strings so method chains keep working
	if e.kind == .call {
		return match e.name {
			'upper', 'lower', 'trim', 'str', 'getenv', 'read_file', 'join' { 'string' }
			'build_compile', 'build_assemble', 'build_link', 'build_exec', 'build_base',
			'build_dir', 'build_join', 'build_root' { 'string' }
			'json_encode', 'format', 'replace', 'pad', 'pad_left', 'repeat', 'sb_new', 'sb_add', 'sb_str' { 'string' }
			'sb_len' { 'int' }
			'cwd', 'json_pretty', 'read_line', 'input' { 'string' }
			else { '' }
		}
	}
	return ''
}

// method_receiver_type resolves the struct type a method call is made on.
// Returns '' when the type is statically unknown (at which point the
// call becomes a dynamic closure invocation via field access).
fn (mut g Gen) method_receiver_type(e Expr) string {
	recv := e.left
	if recv.kind == .ident {
		t := g.types[recv.name] or { '' }
		if t.len > 0 {
			return t
		}
	}
	// enum variant: Color.red  ->  type is "Color"
	if recv.kind == .field && recv.left.kind == .ident {
		key := '${recv.left.name}.${recv.name}'
		if key in g.enum_vals {
			return recv.left.name
		}
	}
	return ''
}

// gen_enum_to_string generates bytecode for `e.to_string()` on an enum value.
// It emits a match statement that maps each integer variant to its string name.
fn (mut g Gen) gen_enum_to_string(enum_name string, recv Expr, line int) ! {
	variants := g.enums[enum_name] or {
		return error('unknown enum "${enum_name}" at line ${line}')
	}
	// store the receiver in a temp local
	subj_idx := g.new_local()
	g.gen_expr(recv)!
	g.emit_store(subj_idx)
	// end label for the match
	end_l := g.new_label()
	for i, v in variants {
		next_l := g.new_label()
		// load subject, push variant integer, compare
		g.emit_load(subj_idx)
		g.code << op_push_i
		g.code << obj.encode_i64(i64(i))
		g.code << op_eq
		g.code << op_jz
		g.code << obj.encode_i64(0)
		g.fixups << Fixup{ name: next_l, off: u32(g.code.len) - 8 }
		// push the variant name as a string
		g.code << op_push_s
		g.code << obj.encode_i64(0)
		g.relocs << obj.Reloc{ offset: u32(g.code.len) - 8, name: v, kind: 1 }
		// jump to end
		g.code << op_jmp
		g.code << obj.encode_i64(0)
		g.fixups << Fixup{ name: end_l, off: u32(g.code.len) - 8 }
		g.emit_label(next_l)
	}
	// else: push "unknown"
	g.code << op_push_s
	g.code << obj.encode_i64(0)
	g.relocs << obj.Reloc{ offset: u32(g.code.len) - 8, name: 'unknown', kind: 1 }
	g.emit_label(end_l)
}

// gen_for_enum generates a for loop that iterates over all variants of an enum.
// for x in Color { ... }  →  for i in 0..count { x = i; ... }  (x typed as Color)
fn (mut g Gen) gen_for_enum(var_name string, enum_name string, body []Stmt, line int) ! {
	variants := g.enums[enum_name] or {
		return error('unknown enum "${enum_name}" at line ${line}')
	}
	count := variants.len
	// i := 0
	var_idx := g.new_local()
	bound_idx := g.new_local()
	g.code << op_push_i
	g.code << obj.encode_i64(0)
	g.emit_store(var_idx)
	g.code << op_push_i
	g.code << obj.encode_i64(i64(count))
	g.emit_store(bound_idx)
	loop_l := g.new_label()
	inc_l := g.new_label()
	end_l := g.new_label()
	g.emit_label(loop_l)
	g.emit_load(var_idx)
	g.emit_load(bound_idx)
	g.code << op_lt
	g.code << op_jz
	g.code << obj.encode_i64(0)
	g.fixups << Fixup{ name: end_l, off: u32(g.code.len) - 8 }
	g.loops << LoopCtx{ break_l: end_l, continue_l: inc_l }
	prev := g.locals[var_name] or { -1 }
	prev_t := g.types[var_name] or { '' }
	g.locals[var_name] = var_idx
	g.types[var_name] = enum_name // type the loop variable as the enum
	for s in body {
		g.gen_stmt(s)!
	}
	if prev >= 0 {
		g.locals[var_name] = prev
	} else {
		g.locals.delete(var_name)
	}
	if prev_t.len > 0 {
		g.types[var_name] = prev_t
	}
	g.loops.delete_last()
	g.emit_label(inc_l)
	g.emit_load(var_idx)
	g.code << op_push_i
	g.code << obj.encode_i64(1)
	g.code << op_add
	g.emit_store(var_idx)
	g.code << op_jmp
	g.code << obj.encode_i64(0)
	g.fixups << Fixup{ name: loop_l, off: u32(g.code.len) - 8 }
	g.emit_label(end_l)
}

// emit_field_name pushes a field name as a string constant. Like string
// literals it goes through a kind-1 relocation so multi-file links rebase it.
fn (mut g Gen) emit_field_name(name string) {
	g.code << op_push_s
	g.code << obj.encode_i64(0)
	g.relocs << obj.Reloc{ offset: u32(g.code.len) - 8, name: name, kind: 1 }
}

fn (mut g Gen) intern(s string) int {
	if s in g.str_map {
		return g.str_map[s]
	}
	idx := g.strings.len
	g.strings << s
	g.str_map[s] = idx
	return idx
}

fn (mut g Gen) new_local() int {
	idx := g.local_cnt
	g.local_cnt++
	return idx
}

fn (mut g Gen) emit_load(idx int) {
	g.code << op_load
	g.code << obj.encode_i64(i64(idx))
}

fn (mut g Gen) emit_store(idx int) {
	g.code << op_store
	g.code << obj.encode_i64(i64(idx))
}

fn (mut g Gen) new_label() string {
	g.next_lbl++
	return 'L${g.next_lbl}'
}

fn (mut g Gen) emit_label(name string) {
	g.labels[name] = g.code.len
}

// ---------------------------------------------------------------------------
// closure capture analysis
//
// A closure (anonymous `fn`) may reference the enclosing function's locals.
// Since the VM compiles each function with its own frame, those references
// are resolved by capturing the values at closure-creation time: the compiler
// scans the body for free variables, registers them as the lambda's leading
// local slots, and emits loads of their current values before op_closure.

// scan_captures returns the enclosing locals a closure body references, in
// first-reference order (stable and deterministic for codegen).
fn (mut g Gen) scan_captures(body []Stmt, fparams []string) []string {
	mut bound := map[string]bool{}
	for p in fparams {
		bound[p] = true
	}
	mut caps := []string{}
	mut seen := map[string]bool{}
	for st in body {
		g.scan_stmt(st, mut bound, mut caps, mut seen)
	}
	return caps
}

fn (mut g Gen) maybe_capture(name string, bound map[string]bool, mut caps []string, mut seen map[string]bool) {
	if name in bound {
		return // bound inside the closure — a plain local
	}
	if name !in g.locals {
		return // not an enclosing local (global fn/const/enum — resolved elsewhere)
	}
	if name !in seen {
		seen[name] = true
		caps << name
	}
}

// collect_defers walks a statement list, gathering the inner statements of
// every `defer` into `out` in source order. Called once per function before
// code generation so all return sites can be redirected to the cleanup block.
fn (mut g Gen) collect_defers(stmts []Stmt, mut out []Stmt) {
	for st in stmts {
		match st.kind {
		.defer_stmt {
			for d in st.body {
				out << d
			}
		}
			.if_stmt {
				g.collect_defers(st.body, mut out)
				g.collect_defers(st.els, mut out)
			}
			.match_stmt {
				for a in st.arms {
					g.collect_defers(a.body, mut out)
				}
				g.collect_defers(st.els_body, mut out)
			}
			.while_stmt, .for_range_stmt, .for_in_stmt, .try_stmt {
				g.collect_defers(st.body, mut out)
				if st.kind == .try_stmt {
					g.collect_defers(st.els, mut out)
				}
			}
			else {}
		}
	}
}

fn (mut g Gen) scan_stmt(st Stmt, mut bound map[string]bool, mut caps []string, mut seen map[string]bool) {
	match st.kind {
		.expr_stmt {
			g.scan_expr(st.expr, mut bound, mut caps, mut seen)
		}
		.let_stmt {
			g.scan_expr(st.expr, mut bound, mut caps, mut seen)
			bound[st.target] = true
		}
		.destruct_stmt {
			g.scan_expr(st.expr, mut bound, mut caps, mut seen)
			for t in st.destruct_targets {
				bound[t] = true
			}
		}
		.assign_stmt {
			// assignment to a name that is not a closure-local references the
			// enclosing local's captured copy
			g.maybe_capture(st.target, bound, mut caps, mut seen)
			bound[st.target] = true
			g.scan_expr(st.expr, mut bound, mut caps, mut seen)
		}
		.index_assign {
			g.scan_expr(st.base, mut bound, mut caps, mut seen)
			g.scan_expr(st.idx, mut bound, mut caps, mut seen)
			g.scan_expr(st.expr, mut bound, mut caps, mut seen)
		}
		.field_assign {
			g.scan_expr(st.base, mut bound, mut caps, mut seen)
			g.scan_expr(st.expr, mut bound, mut caps, mut seen)
		}
		.if_stmt {
			g.scan_expr(st.cond, mut bound, mut caps, mut seen)
			for s in st.body {
				g.scan_stmt(s, mut bound, mut caps, mut seen)
			}
			for s in st.els {
				g.scan_stmt(s, mut bound, mut caps, mut seen)
			}
		}
		.match_stmt {
			g.scan_expr(st.expr, mut bound, mut caps, mut seen)
			for arm in st.arms {
				g.scan_expr(arm.val, mut bound, mut caps, mut seen)
				if arm.is_range {
					g.scan_expr(arm.range_end, mut bound, mut caps, mut seen)
				}
				for s in arm.body {
					g.scan_stmt(s, mut bound, mut caps, mut seen)
				}
			}
			for s in st.els_body {
				g.scan_stmt(s, mut bound, mut caps, mut seen)
			}
		}
		.while_stmt {
			g.scan_expr(st.cond, mut bound, mut caps, mut seen)
			for s in st.body {
				g.scan_stmt(s, mut bound, mut caps, mut seen)
			}
		}
		.for_range_stmt {
			g.scan_expr(st.expr, mut bound, mut caps, mut seen)
			g.scan_expr(st.cond, mut bound, mut caps, mut seen)
			had := st.target in bound
			bound[st.target] = true
			for s in st.body {
				g.scan_stmt(s, mut bound, mut caps, mut seen)
			}
			if !had {
				bound.delete(st.target)
			}
		}
		.for_in_stmt {
			g.scan_expr(st.expr, mut bound, mut caps, mut seen)
			had := st.target in bound
			bound[st.target] = true
			mut had_idx := false
			if st.idx_target.len > 0 {
				had_idx = st.idx_target in bound
				bound[st.idx_target] = true
			}
			for s in st.body {
				g.scan_stmt(s, mut bound, mut caps, mut seen)
			}
			if !had {
				bound.delete(st.target)
			}
			if st.idx_target.len > 0 && !had_idx {
				bound.delete(st.idx_target)
			}
		}
		.ret_stmt {
			if st.has_val {
				g.scan_expr(st.expr, mut bound, mut caps, mut seen)
			}
		}
		.assert_stmt {
			g.scan_expr(st.expr, mut bound, mut caps, mut seen)
		}
		.try_stmt {
			for s in st.body {
				g.scan_stmt(s, mut bound, mut caps, mut seen)
			}
			had := st.target in bound
			bound[st.target] = true
			for s in st.els {
				g.scan_stmt(s, mut bound, mut caps, mut seen)
			}
			if !had {
				bound.delete(st.target)
			}
		}
		.throw_stmt {
			g.scan_expr(st.expr, mut bound, mut caps, mut seen)
		}
		.defer_stmt {
			for s in st.body {
				g.scan_stmt(s, mut bound, mut caps, mut seen)
			}
		}
		.break_stmt, .continue_stmt {}
	}
}

fn (mut g Gen) scan_expr(e Expr, mut bound map[string]bool, mut caps []string, mut seen map[string]bool) {
	match e.kind {
		.ident {
			g.maybe_capture(e.name, bound, mut caps, mut seen)
		}
		.call {
			// a call to an enclosing local holding a closure must capture it too
			g.maybe_capture(e.name, bound, mut caps, mut seen)
			for a in e.args {
				g.scan_expr(a, mut bound, mut caps, mut seen)
			}
		}
		.field {
			g.scan_expr(*e.left, mut bound, mut caps, mut seen)
		}
		.method_call {
			g.scan_expr(*e.left, mut bound, mut caps, mut seen)
			for a in e.args {
				g.scan_expr(a, mut bound, mut caps, mut seen)
			}
		}
		.index {
			g.scan_expr(*e.left, mut bound, mut caps, mut seen)
			g.scan_expr(*e.right, mut bound, mut caps, mut seen)
		}
		.slice {
			g.scan_expr(*e.left, mut bound, mut caps, mut seen)
			g.scan_expr(*e.right, mut bound, mut caps, mut seen)
			g.scan_expr(*e.extra, mut bound, mut caps, mut seen)
		}
		.unary {
			g.scan_expr(*e.right, mut bound, mut caps, mut seen)
		}
		.binary {
			g.scan_expr(*e.left, mut bound, mut caps, mut seen)
			g.scan_expr(*e.right, mut bound, mut caps, mut seen)
		}
		.array_lit {
			for el in e.elems {
				g.scan_expr(el, mut bound, mut caps, mut seen)
			}
		}
		.struct_lit {
			for f in e.fields {
				g.scan_expr(f.val, mut bound, mut caps, mut seen)
			}
		}
		.anon_fn {
			// a nested closure: its parameters bind inside it, but references to
			// enclosing locals still belong to this closure's capture set
			mut saved := map[string]bool{}
			for p in e.fparams {
				saved[p] = p in bound
				bound[p] = true
			}
			for s in e.fn_body {
				g.scan_stmt(s, mut bound, mut caps, mut seen)
			}
			for p in e.fparams {
				if !saved[p] {
					bound.delete(p)
				}
			}
		}
		else {}
	}
}
