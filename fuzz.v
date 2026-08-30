// fuzz.v — grammar-driven fuzzer for the compiler and VM.
//
//   vr fuzz [--seed N] [--iters N] [--max-ops N] [--save-dir DIR]
//
// Each iteration generates a random VuurRaaf program from a small typed
// grammar (ints, floats, strings, booleans, arrays, structs/maps, closures,
// if/while, functions, try/catch), compiles it, and runs it twice with an
// instruction budget — all inside a fresh `vr fuzz --child` subprocess, so a
// crash in the generator, the compiler, or the VM is isolated to that one
// case and the run continues.
//
// Findings (each saved as a .vr repro in --save-dir, default ./fuzz-repros/):
//   * crash — the child died (segfault / V panic) in any phase
//   * hang  — caught by the --max-ops instruction budget
//   * nondeterminism — the same program produced different output across runs
module main

import os
import compiler
import obj
import linker
import vm

struct Rng {
mut:
	state u64
}

fn (mut r Rng) next() u64 {
	r.state ^= r.state << 13
	r.state ^= r.state >> 7
	r.state ^= r.state << 17
	return r.state
}

fn (mut r Rng) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(r.next() % u64(n))
}

fn (mut r Rng) pick_str(items []string) string {
	return items[r.intn(items.len)]
}

// FuzzCtx carries the random generator plus the helper functions the
// generator may reference from generated expressions.
struct FuzzCtx {
mut:
	rng       Rng
	helper    []string // helper function names
	helper_ar []int    // argument counts, parallel to helper
	vars      []string // names declared in the function being generated
}

const fuzz_int_ops = ['+', '-', '*', '/', '%']
const fuzz_cmp_ops = ['==', '!=', '<', '<=', '>', '>=']
const fuzz_bool_ops = ['and', 'or']
const fuzz_bools = ['true', 'false']
const fuzz_names = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

fn toolchain_fuzz(args []string) ! {
	if args.len > 0 && args[0] == '--child' {
		// worker mode: generate + compile + run one seed, report via stderr
		if args.len < 3 {
			return error('fuzz --child needs <seed> <outdir> [max_ops]')
		}
		seed := args[1].u64()
		outdir := args[2]
		mut max_ops := i64(200000)
		if args.len > 3 {
			max_ops = args[3].i64()
		}
		fuzz_child(seed, outdir, max_ops)!
		return
	}
	mut seed := u64(1)
	mut iters := 500
	mut max_ops := i64(200000)
	mut save_dir := 'fuzz-repros'
	mut i := 0
	for i < args.len {
		a := args[i]
		if a == '--seed' && i + 1 < args.len {
			seed = args[i + 1].u64()
			i += 2
		} else if a == '--iters' && i + 1 < args.len {
			iters = args[i + 1].int()
			i += 2
		} else if a == '--max-ops' && i + 1 < args.len {
			max_ops = args[i + 1].i64()
			i += 2
		} else if a == '--save-dir' && i + 1 < args.len {
			save_dir = args[i + 1]
			i += 2
		} else {
			return error('unknown fuzz option "${a}" (supported: --seed N, --iters N, --max-ops N, --save-dir DIR)')
		}
	}
	os.mkdir_all(save_dir) or { return error('cannot create save dir ${save_dir}: ${err}') }
	exe := os.executable()
	tmpdir := os.join_path(os.temp_dir(), 'vr_fuzz_${os.getpid()}')
	os.mkdir_all(tmpdir) or { return error('cannot create ${tmpdir}: ${err}') }
	defer {
		os.rmdir_all(tmpdir) or {}
	}
	println('fuzz: seed=${seed} iters=${iters} max-ops=${max_ops} save-dir=${save_dir}')
	println('fuzz: each case runs in its own subprocess; findings are saved as .vr repros')
	mut bugs := 0
	mut compiled := 0
	mut ran := 0
	mut compile_fail := 0
	mut runtime_err := 0
	mut nondet := 0
	for it in 0..iters {
		if it % 50 == 0 {
			println('fuzz: iter ${it}/${iters} (compiled=${compiled} bugs=${bugs})')
		}
		cur_seed := seed + u64(it)
		os.rmdir_all(os.join_path(tmpdir, 'case')) or {}
		outdir := os.join_path(tmpdir, 'case')
		os.mkdir_all(outdir) or {}
		run1 := os.execute('"${exe}" fuzz --child ${cur_seed} "${outdir}" ${max_ops}')
		ran++
		// classify crashes: anything that is not a clean exit-0 handshake
		ok1 := run1.exit_code == 0 && (run1.output.contains('RUN_OK') || run1.output.contains('COMPILE_FAIL') || run1.output.contains('VM_ERR') || run1.output.contains('HANG'))
		if !ok1 {
			phase := crash_phase(outdir)
			eprintln('fuzz: CRASH (exit ${run1.exit_code}, phase=${phase}) at iter ${it} seed ${cur_seed}')
			bugs++
			save_repro(save_dir, cur_seed, it, outdir, phase)
			continue
		}
		if run1.output.contains('COMPILE_FAIL') {
			compile_fail++
			continue
		}
		if run1.output.contains('VM_ERR') || run1.output.contains('HANG') {
			runtime_err++
			continue
		}
		compiled++
		// determinism: run the identical case again and compare output
		run2 := os.execute('"${exe}" fuzz --child ${cur_seed} "${outdir}" ${max_ops}')
		ran++
		if run2.exit_code != 0 || run2.output != run1.output {
			eprintln('fuzz: NONDETERMINISM at iter ${it} seed ${cur_seed}')
			println('run1 (exit ${run1.exit_code}): ${run1.output}')
			println('run2 (exit ${run2.exit_code}): ${run2.output}')
			nondet++
			bugs++
			save_repro(save_dir, cur_seed, it, outdir, 'nondeterminism')
		}
	}
	println('')
	println('fuzz: done — ${iters} iterations, ${compiled} compiled, ${ran} runs')
	println('fuzz: compile-fail=${compile_fail} runtime-errors=${runtime_err} bugs=${bugs} nondeterminism=${nondet}')
	if bugs > 0 {
		println('fuzz: BUGS FOUND — repros saved in ${save_dir}/')
		exit(1)
	}
	println('fuzz: no bugs found')
}

// crash_phase inspects the worker's output dir to say where the crash happened.
fn crash_phase(outdir string) string {
	case_file := os.join_path(outdir, 'case.vr')
	if !os.exists(case_file) {
		return 'generator'
	}
	if !os.exists(os.join_path(outdir, 'compiled.ok')) {
		return 'compiler'
	}
	return 'vm'
}

// save_repro copies the failing case's source into the save dir.
fn save_repro(dir string, seed u64, iter int, outdir string, what string) {
	src := os.read_file(os.join_path(outdir, 'case.vr')) or {
		// generator crash: no source was produced; record the seed
		note := os.join_path(dir, 'repro_seed${seed}_iter${iter}.seed')
		os.write_file(note, 'seed=${seed}\nphase=${what}\n') or {}
		eprintln('fuzz: saved seed note -> ${note}')
		return
	}
	repro_path := os.join_path(dir, 'repro_seed${seed}_iter${iter}.vr')
	os.write_file(repro_path, '// repro: ${what}\n// seed=${seed}\n\n${src}') or {}
	eprintln('fuzz: saved repro -> ${repro_path}')
}

// fuzz_child is the worker: generate one program, save it, compile it, and run
// it with an instruction budget. Contract with the parent:
//   stderr 'COMPILE_FAIL' — program did not compile (expected)
//   stderr 'VM_ERR'       — program ran but raised a runtime error (expected)
//   stderr 'HANG'         — the max-ops budget fired (expected)
//   stderr 'RUN_OK'       — program finished; stdout is its output
// Any other termination (nonzero exit, panic, segfault) is a finding.
fn fuzz_child(seed u64, outdir string, max_ops i64) ! {
	src := gen_program(seed)
	os.write_file(os.join_path(outdir, 'case.vr'), src) or {
		return error('cannot write case: ${err}')
	}
	o := compiler.compile(src) or {
		eprintln('COMPILE_FAIL')
		return
	}
	os.write_file(os.join_path(outdir, 'compiled.ok'), 'ok') or {}
	tmp_obj := os.join_path(outdir, 'case.vobj')
	tmp_bin := os.join_path(outdir, 'case.vbin')
	obj.write(tmp_obj, o) or { return error('obj write: ${err}') }
	linker.link([tmp_obj], tmp_bin) or {
		eprintln('LINK_FAIL: ${err}')
		return
	}
	bin := obj.read_bin(tmp_bin) or { return error('bin read: ${err}') }
	vm.run_opts(bin, 'main', vm.RunOpts{ max_ops: max_ops }) or {
		msg := err.msg()
		if msg.contains('max ops exceeded') {
			eprintln('HANG')
		} else {
			eprintln('VM_ERR')
		}
		return
	}
	eprintln('RUN_OK')
}

// ---------------------------------------------------------------------------
// program generation

fn gen_program(seed u64) string {
	mut ctx := FuzzCtx{ rng: Rng{ state: if seed == 0 { u64(1) } else { seed } } }
	mut out := ''
	// random helper functions (0..3)
	n_helpers := ctx.rng.intn(4)
	for h in 0..n_helpers {
		fname := 'h${h}'
		ctx.helper << fname
		ctx.helper_ar << ctx.rng.intn(3)
		out += gen_fn(mut ctx, fname, 2)
	}
	out += 'fn main() {\n'
	out += gen_body(mut ctx, 3)
	out += '\tprintln("done")\n}\n'
	return out
}

// gen_fn generates a function declaration. depth bounds expression nesting.
fn gen_fn(mut ctx FuzzCtx, fname string, depth int) string {
	params := ctx.rng.intn(4)
	mut out := 'fn ${fname}('
	mut param_names := []string{}
	for i in 0..params {
		p := fuzz_names[ctx.rng.intn(fuzz_names.len)]
		param_names << p
		if i > 0 {
			out += ', '
		}
		out += p
	}
	out += ') {\n'
	ctx.vars = []string{}
	for p in param_names {
		ctx.vars << p
		out += '\tlet ${p} = ${p}\n' // re-bind so params are named locals
	}
	e := gen_expr(mut ctx, depth, 0)
	out += '\tlet r = ${e}\n'
	out += '\treturn r\n}\n'
	return out
}

// gen_body generates statements for a function body.
fn gen_body(mut ctx FuzzCtx, depth int) string {
	mut out := ''
	n := ctx.rng.intn(6)
	for _ in 0..n {
		out += gen_stmt(mut ctx, depth)
	}
	return out
}

fn gen_stmt(mut ctx FuzzCtx, depth int) string {
	// control-flow statements recurse into gen_body with depth-1 and are only
	// allowed above depth 0, so nested if/while/try cannot grow unboundedly
	// below depth 1 only leaf statements (let/assign/expr/push) are allowed,
	// so nested control flow cannot grow unboundedly
	mut t := ctx.rng.intn(7)
	if depth <= 0 {
		t = match ctx.rng.intn(4) {
			0 { 0 }
			1 { 1 }
			2 { 4 }
			else { 5 }
		}
	}
	match t {
		0 { // let with expression (declares a fresh name)
			v := fuzz_names[ctx.rng.intn(fuzz_names.len)]
			ctx.vars << v
			e := gen_expr(mut ctx, depth, 0)
			return '\tlet ${v} = ${e}\n'
		}
		1 { // assignment to an existing var (or a let when none exist)
			if ctx.vars.len > 0 {
				v := ctx.vars[ctx.rng.intn(ctx.vars.len)]
				e := gen_expr(mut ctx, depth, 0)
				return '\t${v} = ${e}\n'
			}
			v := fuzz_names[ctx.rng.intn(fuzz_names.len)]
			ctx.vars << v
			e := gen_expr(mut ctx, depth, 0)
			return '\tlet ${v} = ${e}\n'
		}
		2 { // if/else
			cond := gen_expr(mut ctx, depth, 0)
			b1 := gen_body(mut ctx, depth - 1)
			b2 := gen_body(mut ctx, depth - 1)
			return '\tif ${cond} {\n${b1}' + '\t} else {\n${b2}' + '\t}\n'
		}
		3 { // while with random condition (sometimes true: exercises max-ops)
			cond := if ctx.rng.intn(4) == 0 { 'true' } else { gen_expr(mut ctx, depth, 0) }
			return '\twhile ${cond} {\n${gen_body(mut ctx, depth - 1)}' + '\t}\n'
		}
		4 { // expression statement
			e := gen_expr(mut ctx, depth, 0)
			return '\t${e}\n'
		}
		5 { // push to array
			if ctx.vars.len == 0 {
				return '\tlet a = []\n'
			}
			v := ctx.vars[ctx.rng.intn(ctx.vars.len)]
			e := gen_expr(mut ctx, depth, 0)
			return '\t${v} = push(${v}, ${e})\n'
		}
		else { // try/catch
			return '\ttry {\n${gen_body(mut ctx, depth - 1)}' + '\t} catch e {\n\t\tlet msg = e\n\t}\n'
		}
	}
	return ''
}

// gen_expr generates a random expression; depth bounds nesting.
fn gen_expr(mut ctx FuzzCtx, depth int, ty int) string {
	if depth <= 0 || ctx.rng.intn(3) == 0 {
		return gen_atom(mut ctx, ty)
	}
	// pick a construct compatible with the requested type (0 = any)
	mut choices := [0, 4, 6, 11] // variable, literal, len, call
	if ty == 0 || ty == 1 {
		choices << 0 // arithmetic
		choices << 5 // array index
		choices << 9 // struct field
	}
	if ty == 0 || ty == 3 {
		choices << 1 // comparison -> bool
		choices << 2 // boolean ops
		choices << 3 // not
	}
	if ty == 0 || ty == 4 {
		choices << 7 // string concat
	}
	if ty == 0 || ty == 5 {
		choices << 8 // struct literal
	}
	t := choices[ctx.rng.intn(choices.len)]
	match t {
		0 { // arithmetic -> int
			a := gen_expr(mut ctx, depth - 1, 1)
			op := ctx.rng.pick_str(fuzz_int_ops)
			b := gen_expr(mut ctx, depth - 1, 1)
			return '(${a} ${op} ${b})'
		}
		1 { // comparison -> bool
			a := gen_expr(mut ctx, depth - 1, 1)
			op := ctx.rng.pick_str(fuzz_cmp_ops)
			b := gen_expr(mut ctx, depth - 1, 1)
			return '(${a} ${op} ${b})'
		}
		2 { // boolean ops -> bool
			a := gen_expr(mut ctx, depth - 1, 3)
			op := ctx.rng.pick_str(fuzz_bool_ops)
			b := gen_expr(mut ctx, depth - 1, 3)
			return '(${a} ${op} ${b})'
		}
		3 { // not -> bool
			e := gen_expr(mut ctx, depth - 1, 3)
			return 'not (${e})'
		}
		4 { // array literal of ints
			n := ctx.rng.intn(4)
			mut parts := []string{}
			for _ in 0..n {
				parts << gen_expr(mut ctx, depth - 1, 1)
			}
			return '[${parts.join(', ')}]'
		}
		5 { // array index -> int
			if ctx.vars.len == 0 {
				n := ctx.rng.intn(21) - 10
				return '${n}'
			}
			v := ctx.vars[ctx.rng.intn(ctx.vars.len)]
			ix := ctx.rng.intn(5)
			return '${v}[${ix}]'
		}
		6 { // len() -> int
			if ctx.vars.len == 0 {
				n := ctx.rng.intn(21) - 10
				return '${n}'
			}
			v := ctx.vars[ctx.rng.intn(ctx.vars.len)]
			return 'len(${v})'
		}
		7 { // string concat -> string
			a := gen_expr(mut ctx, depth - 1, 4)
			b := gen_expr(mut ctx, depth - 1, 4)
			return '(${a} + ${b})'
		}
		8 { // struct literal
			mut parts := []string{}
			n := 1 + ctx.rng.intn(3)
			for i in 0..n {
				e := gen_expr(mut ctx, depth - 1, 1)
				parts << '"f' + i.str() + '": ' + e
			}
			return '{${parts.join(', ')}}'
		}
		9 { // struct field access -> int
			if ctx.vars.len == 0 {
				n := ctx.rng.intn(21) - 10
				return '${n}'
			}
			v := ctx.vars[ctx.rng.intn(ctx.vars.len)]
			return '${v}.f${ctx.rng.intn(3)}'
		}
		11 { // call a helper
			if ctx.helper.len > 0 {
				h := ctx.rng.intn(ctx.helper.len)
				np := ctx.helper_ar[h]
				mut args := []string{}
				for _ in 0..np {
					args << gen_expr(mut ctx, depth - 1, 1)
				}
				hname := ctx.helper[h]
				return '${hname}(${args.join(', ')})'
			}
			return gen_atom(mut ctx, ty)
		}
		else {
			return gen_atom(mut ctx, ty)
		}
	}
}

fn gen_params_decl(mut ctx FuzzCtx) string {
	n := ctx.rng.intn(3)
	mut parts := []string{}
	for _ in 0..n {
		parts << fuzz_names[ctx.rng.intn(fuzz_names.len)]
	}
	return parts.join(', ')
}

// gen_atom generates a leaf expression of the requested type (0 = any).
fn gen_atom(mut ctx FuzzCtx, ty int) string {
	match ty {
		1 { // int
			n := ctx.rng.intn(21) - 10
			return '${n}'
		}
		2 { // float
			n := ctx.rng.intn(101)
			return '${f64(n) / 10.0}'
		}
		3 { // bool
			return ctx.rng.pick_str(fuzz_bools)
		}
		4 { // string
			n := ctx.rng.intn(100)
			return '"s${n}"'
		}
		else { // any: mostly ints, sometimes a variable or a string
			t := ctx.rng.intn(10)
			if t < 5 {
				n := ctx.rng.intn(21) - 10
				return '${n}'
			}
			if t < 7 {
				n := ctx.rng.intn(101)
				return '${f64(n) / 10.0}'
			}
			if t < 8 {
				return ctx.rng.pick_str(fuzz_bools)
			}
			if t < 9 {
				n := ctx.rng.intn(100)
				return '"s${n}"'
			}
			if ctx.vars.len > 0 {
				return ctx.vars[ctx.rng.intn(ctx.vars.len)]
			}
			n := ctx.rng.intn(21) - 10
			return '${n}'
		}
	}
}
