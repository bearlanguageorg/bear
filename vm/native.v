// native.v — host builtins for the VuurRaaf VM.
//
// The op_native instruction carries a builtin id and an argument count. Each
// builtin pops its arguments off the stack (left-to-right push order means the
// last argument is on top) and pushes a single result (except exit(), which
// halts the machine). This is where the language touches the host: file I/O,
// environment, time, randomness, and the math/collection helpers.
module vm

import os
import math
import rand
import time
import net.http
import obj
import compiler
import assembler
import linker
import regex
import encoding.base64
import crypto.sha256
import crypto.md5
import encoding.csv

fn (mut v Vm) native(id int, _argc int) ! {
	match id {
		native_abs {
			x := v.pop()!
			if v.is_float(x) {
				v.push(v.push_float(math.abs(v.fval(x))))!
			} else {
				val := v.dec_int(x)
				v.push(v.enc_int(if val < 0 { -val } else { val }))!
			}
		}
		native_min {
			b := v.pop()!
			a := v.pop()!
			if v.is_float(a) || v.is_float(b) {
				v.push(v.push_float(math.min(v.to_f64(a), v.to_f64(b))))!
			} else {
				x := v.dec_int(a)
				y := v.dec_int(b)
				v.push(v.enc_int(if x < y { x } else { y }))!
			}
		}
		native_max {
			b := v.pop()!
			a := v.pop()!
			if v.is_float(a) || v.is_float(b) {
				v.push(v.push_float(math.max(v.to_f64(a), v.to_f64(b))))!
			} else {
				x := v.dec_int(a)
				y := v.dec_int(b)
				v.push(v.enc_int(if x > y { x } else { y }))!
			}
		}
		native_pow {
			b := v.pop()!
			a := v.pop()!
			v.push(v.push_float(math.pow(v.to_f64(a), v.to_f64(b))))!
		}
		native_sqrt {
			x := v.pop()!
			v.push(v.push_float(math.sqrt(v.to_f64(x))))!
		}
		native_floor {
			x := v.pop()!
			v.push(v.enc_int(i64(math.floor(v.to_f64(x)))))!
		}
		native_ceil {
			x := v.pop()!
			v.push(v.enc_int(i64(math.ceil(v.to_f64(x)))))!
		}
		native_round {
			x := v.pop()!
			v.push(v.enc_int(i64(math.round(v.to_f64(x)))))!
		}
		native_rand {
			v.push(v.push_float(rand.f64()))!
		}
		native_rand_int {
			n := int(v.dec_int(v.pop()!))
			if n <= 0 {
				return error('rand_int() expects a positive bound')
			}
			v.push(v.enc_int(i64(rand.intn(n) or { return error('rand_int() failed') })))!
		}
		native_int {
			x := v.pop()!
			if v.is_str(x) && v.valid_handle(x) {
				v.push(v.enc_int(i64(v.strings[v.hand(x)].i64())))!
			} else if v.is_float(x) {
				v.push(v.enc_int(i64(v.fval(x))))!
			} else if v.is_arr(x) || v.is_struct(x) {
				return error('cannot convert a ${v.type_name(x)} to int')
			} else {
				v.push(x)!
			}
		}
		native_str {
			x := v.pop()!
			v.push(v.alloc_str(v.val_str(x, 0)))!
		}
		native_float {
			x := v.pop()!
			if v.is_str(x) && v.valid_handle(x) {
				v.push(v.push_float(v.strings[v.hand(x)].f64()))!
			} else if v.is_float(x) {
				v.push(x)!
			} else if v.is_arr(x) || v.is_struct(x) {
				return error('cannot convert a ${v.type_name(x)} to float')
			} else {
				v.push(v.push_float(f64(v.dec_int(x))))!
			}
		}
		native_type {
			x := v.pop()!
			v.push(v.alloc_str(v.type_name(x)))!
		}
		native_type_info {
			x := v.pop()!
			v.push(v.type_info_value(x))!
		}
		native_range {
			b := v.pop()!
			a := v.pop()!
			v.push(v.range_value(a, b))!
		}
		native_split {
			delim := v.pop_str()!
			s := v.pop_str()!
			parts := s.split(delim)
			mut arr := []i64{}
			for p in parts {
				v.strings << p
				arr << v.mkstr(v.strings.len - 1)
			}
			v.arrays << arr
			v.push(v.mkarr(v.arrays.len - 1))!
		}
		native_join {
			delim := v.pop_str()!
			h := v.pop()!
			if !v.is_arr(h) || !v.valid_arr_handle(h) {
				return error('join() expects an array as its first argument')
			}
			a := v.arrays[v.hand(h)]
			mut parts := []string{}
			for x in a {
				if v.is_str(x) && v.valid_handle(x) {
					parts << v.strings[v.hand(x)]
				} else {
					parts << v.val_str(x, 0)
				}
			}
			v.push(v.alloc_str(parts.join(delim)))!
		}
		native_contains {
			sub := v.pop_str()!
			s := v.pop_str()!
			v.push(v.enc_int(bool_i64(s.contains(sub))))!
		}
		native_starts_with {
			sub := v.pop_str()!
			s := v.pop_str()!
			v.push(v.enc_int(bool_i64(s.starts_with(sub))))!
		}
		native_ends_with {
			sub := v.pop_str()!
			s := v.pop_str()!
			v.push(v.enc_int(bool_i64(s.ends_with(sub))))!
		}
		native_trim {
			s := v.pop_str()!
			v.push(v.alloc_str(s.trim_space()))!
		}
		native_lower {
			s := v.pop_str()!
			v.push(v.alloc_str(s.to_lower()))!
		}
		native_upper {
			s := v.pop_str()!
			v.push(v.alloc_str(s.to_upper()))!
		}
		native_pop {
			h := v.pop()!
			if !v.is_arr(h) || !v.valid_arr_handle(h) {
				return error('pop() expects an array')
			}
			mut a := v.arrays[v.hand(h)]
			if a.len == 0 {
				return error('pop() on an empty array')
			}
			val := a[a.len - 1]
			v.arrays[v.hand(h)] = a[..a.len - 1]
			v.push(val)!
		}
		native_insert {
			val := v.pop()!
			idx := int(v.dec_int(v.pop()!))
			h := v.pop()!
			if !v.is_arr(h) || !v.valid_arr_handle(h) {
				return error('insert() expects an array as its first argument')
			}
			a := v.arrays[v.hand(h)]
			if idx < 0 || idx > a.len {
				return error('insert index ${idx} out of bounds (len ${a.len})')
			}
			mut na := []i64{}
			for i, x in a {
				if i == idx {
					na << val
				}
				na << x
			}
			if idx == a.len {
				na << val
			}
			v.arrays[v.hand(h)] = na
			v.push(h)!
		}
		native_remove {
			idx := int(v.dec_int(v.pop()!))
			h := v.pop()!
			if !v.is_arr(h) || !v.valid_arr_handle(h) {
				return error('remove() expects an array as its first argument')
			}
			a := v.arrays[v.hand(h)]
			if idx < 0 || idx >= a.len {
				return error('remove index ${idx} out of bounds (len ${a.len})')
			}
			mut na := []i64{}
			for i, x in a {
				if i != idx {
					na << x
				}
			}
			v.arrays[v.hand(h)] = na
			v.push(h)!
		}
		native_sort {
			h := v.pop()!
			if !v.is_arr(h) || !v.valid_arr_handle(h) {
				return error('sort() expects an array')
			}
			mut a := v.arrays[v.hand(h)]
			// merge sort: guaranteed O(n log n) (insertion sort was O(n^2) on
			// large or reversed inputs) and stable, so equal elements keep
			// their original order
			mut tmp := []i64{len: a.len}
			v.merge_sort(mut a, mut tmp, 0, a.len)
			v.push(h)!
		}
		native_clone {
			x := v.pop()!
			if v.is_arr(x) && v.valid_arr_handle(x) {
				v.arrays << v.arrays[v.hand(x)].clone()
				v.push(v.mkarr(v.arrays.len - 1))!
		} else if v.is_struct(x) && v.valid_struct_handle(x) {
			s := v.structs[v.hand(x)]
			v.structs << StructVal{ fields: s.fields.clone(), by_name: s.by_name.clone() }
			v.push(v.mkstruct_handle(v.structs.len - 1))!
		} else if v.is_str(x) && v.valid_handle(x) {
				v.push(v.alloc_str(v.strings[v.hand(x)]))!
			} else if v.is_float(x) {
				v.push(v.push_float(v.fval(x)))!
			} else {
				v.push(x)!
			}
		}
		native_reverse {
			h := v.pop()!
			if !v.is_arr(h) || !v.valid_arr_handle(h) {
				return error('reverse() expects an array')
			}
			mut a := v.arrays[v.hand(h)]
			for i in 0..a.len / 2 {
				a[i], a[a.len - 1 - i] = a[a.len - 1 - i], a[i]
			}
			v.push(h)!
		}
		native_index_of {
			val := v.pop()!
			h := v.pop()!
			if v.is_arr(h) && v.valid_arr_handle(h) {
				a := v.arrays[v.hand(h)]
				for i, x in a {
					if v.cmp(x, val, '==')! == 1 {
						v.push(v.enc_int(i64(i)))!
						return
					}
				}
				v.push(v.enc_int(-1))!
				return
			}
			if v.is_str(h) && v.valid_handle(h) {
				if !v.is_str(val) || !v.valid_handle(val) {
					return error('index_of() on a string expects a string needle')
				}
				s := v.strings[v.hand(h)]
				needle := v.strings[v.hand(val)]
				byte_idx := s.index(needle) or { -1 }
				if byte_idx < 0 {
					v.push(v.enc_int(-1))!
					return
				}
				// convert byte offset to a rune index so UTF-8 strings count characters
				rune_idx := s[..byte_idx].runes().len
				v.push(v.enc_int(i64(rune_idx)))!
				return
			}
			return error('index_of() expects an array or string as its first argument')
		}
		native_args {
			mut arr := []i64{}
			for s in v.prog_args {
				v.strings << s
				arr << v.mkstr(v.strings.len - 1)
			}
			v.arrays << arr
			v.push(v.mkarr(v.arrays.len - 1))!
		}
		native_getenv {
			name := v.pop_str()!
			v.push(v.alloc_str(os.getenv(name)))!
		}
		native_setenv {
			val := v.pop_str()!
			name := v.pop_str()!
			os.setenv(name, val, true)
			v.push(v.enc_int(0))!
		}
		native_exit {
			code := int(v.dec_int(v.pop()!))
			v.exit_code = i64(code)
			v.did_exit = true
			v.halted = true
		}
		native_time {
			v.push(v.push_float(f64(time.now().unix_milli()) / 1000.0))!
		}
		native_sleep {
			ms := int(v.dec_int(v.pop()!))
			time.sleep(time.Duration(ms) * time.millisecond)
			v.push(v.enc_int(0))!
		}
		native_read_file {
			path := v.pop_str()!
			content := os.read_file(path) or { return error('cannot read file "${path}": ${err}') }
			v.push(v.alloc_str(content))!
		}
		native_write_file {
			content := v.pop_str()!
			path := v.pop_str()!
			os.write_file(path, content) or { return error('cannot write file "${path}": ${err}') }
			v.push(v.enc_int(0))!
		}
		native_eprint {
			x := v.pop()!
			eprintln(v.val_str(x, 0))
		}
		// -------------------------------------------------------------------
		// build-module builtins (.vrmm) — these let a VuurRaaf program drive
		// the toolchain itself, the way V's .vsh scripts drive `v build`.
		native_build_compile {
			out := v.pop_str()!
			src := v.pop_str()!
			o := compiler.compile_file(src) or { return error('build_compile: ${err.msg()}') }
			o_path := if out.len == 0 { src.all_before_last('.') + '.vobj' } else { out }
			obj.write(o_path, o) or { return error('build_compile: cannot write ${o_path}: ${err.msg()}') }
			println('compiled ${src} -> ${o_path} (${o.code.len} bytes code, ${o.symbols.len} symbols)')
			v.push(v.alloc_str(o_path))!
		}
		native_build_assemble {
			out := v.pop_str()!
			src := v.pop_str()!
			o := assembler.assemble_file(src) or { return error('build_assemble: ${err.msg()}') }
			o_path := if out.len == 0 { src.all_before_last('.') + '.vobj' } else { out }
			obj.write(o_path, o) or { return error('build_assemble: cannot write ${o_path}: ${err.msg()}') }
			println('assembled ${src} -> ${o_path} (${o.code.len} bytes code)')
			v.push(v.alloc_str(o_path))!
		}
		native_build_link {
			out := v.pop_str()!
			h := v.pop()!
			if !v.is_arr(h) || !v.valid_arr_handle(h) {
				return error('build_link() expects an array of object files as its first argument')
			}
			mut objs := []string{}
			for x in v.arrays[v.hand(h)] {
				if !v.is_str(x) || !v.valid_handle(x) {
					return error('build_link() expects string paths inside the object array')
				}
				objs << v.strings[v.hand(x)]
			}
			if objs.len == 0 {
				return error('build_link() needs at least one object file')
			}
			o_path := if out.len == 0 { os.base(objs[0]).all_before_last('.') + '.vbin' } else { out }
			linker.link(objs, o_path) or { return error('build_link: ${err.msg()}') }
			println('linked ${objs.len} object file(s) -> ${o_path}')
			v.push(v.alloc_str(o_path))!
		}
		native_build_run {
			f := v.pop_str()!
			if f.ends_with('.vbin') {
				bin := obj.read_bin(f) or { return error('build_run: ${err.msg()}') }
				code := run_with_args(bin, 'main', false, []string{}) or {
					return error('build_run: ${err.msg()}')
				}
				v.push(v.enc_int(code))!
				return
			}
			if !f.ends_with('.vr') {
				return error('build_run() expects a .vr or .vbin file')
			}
			tmp_obj := os.join_path(os.temp_dir(), 'vr_build_${os.getpid()}.vobj')
			tmp_bin := os.join_path(os.temp_dir(), 'vr_build_${os.getpid()}.vbin')
			defer {
				os.rm(tmp_obj) or {}
				os.rm(tmp_bin) or {}
			}
			o := compiler.compile_file(f) or { return error('build_run: ${err.msg()}') }
			obj.write(tmp_obj, o) or { return error('build_run: ${err.msg()}') }
			linker.link([tmp_obj], tmp_bin) or { return error('build_run: ${err.msg()}') }
			bin := obj.read_bin(tmp_bin) or { return error('build_run: ${err.msg()}') }
			code := run_with_args(bin, 'main', false, []string{}) or {
				return error('build_run: ${err.msg()}')
			}
			v.push(v.enc_int(code))!
		}
		native_build_test {
			src := v.pop_str()!
			o := compiler.compile_file(src) or { return error('build_test: ${err.msg()}') }
			mut tests := []string{}
			for s in o.symbols {
				if s.name.starts_with('test_') {
					tests << s.name
				}
			}
			if tests.len == 0 {
				return error('build_test: no test_* functions found in ${src}')
			}
			tmp_obj := os.join_path(os.temp_dir(), 'vr_build_${os.getpid()}.vobj')
			tmp_bin := os.join_path(os.temp_dir(), 'vr_build_${os.getpid()}.vbin')
			defer {
				os.rm(tmp_obj) or {}
				os.rm(tmp_bin) or {}
			}
			obj.write(tmp_obj, o) or { return error('build_test: ${err.msg()}') }
			linker.link([tmp_obj], tmp_bin) or { return error('build_test: ${err.msg()}') }
			bin := obj.read_bin(tmp_bin) or { return error('build_test: ${err.msg()}') }
			mut passes := 0
			mut fails := 0
			for t in tests {
				run(bin, t, false) or {
					eprintln('  FAIL  ${t}  —  ${err}')
					fails++
					continue
				}
				println('  PASS  ${t}')
				passes++
			}
			if fails > 0 {
				return error('build_test: ${fails} of ${tests.len} test(s) failed in ${src}')
			}
			println('${passes} test(s) passed')
			v.push(v.enc_int(i64(passes)))!
		}
		native_build_bench {
			n := int(v.dec_int(v.pop()!))
			src := v.pop_str()!
			if n < 1 {
				return error('build_bench() expects a positive iteration count')
			}
			tmp_obj := os.join_path(os.temp_dir(), 'vr_build_${os.getpid()}.vobj')
			tmp_bin := os.join_path(os.temp_dir(), 'vr_build_${os.getpid()}.vbin')
			defer {
				os.rm(tmp_obj) or {}
				os.rm(tmp_bin) or {}
			}
			o := compiler.compile_file(src) or { return error('build_bench: ${err.msg()}') }
			obj.write(tmp_obj, o) or { return error('build_bench: ${err.msg()}') }
			linker.link([tmp_obj], tmp_bin) or { return error('build_bench: ${err.msg()}') }
			bin := obj.read_bin(tmp_bin) or { return error('build_bench: ${err.msg()}') }
			start := time.now().unix_milli()
			for _ in 0..n {
				run(bin, 'main', false) or { return error('build_bench: ${err.msg()}') }
			}
			ms := time.now().unix_milli() - start
			rate := if ms > 0 { f64(n) / (f64(ms) / 1000.0) } else { f64(0) }
			println('bench: ${n} runs of main() in ${ms}ms (${rate:.0} runs/s)')
			v.push(v.enc_int(0))!
		}
		native_build_clean {
			mut n := 0
			if files := os.ls('.') {
				for f in files {
					if f.ends_with('.vobj') || f.ends_with('.vbin') {
						os.rm(f) or {}
						n++
					}
				}
			}
			println('cleaned ${n} artifact(s)')
			v.push(v.enc_int(i64(n)))!
		}
		native_build_exec {
			cmd := v.pop_str()!
			res := os.execute(cmd)
			if res.exit_code != 0 {
				return error('build_exec: "${cmd}" failed with exit code ${res.exit_code}: ${res.output}')
			}
			v.push(v.alloc_str(res.output))!
		}
		native_build_exec_status {
			cmd := v.pop_str()!
			res := os.execute(cmd)
			v.push(v.enc_int(i64(res.exit_code)))!
		}
		native_build_exists {
			p := v.pop_str()!
			v.push(v.enc_int(bool_i64(os.exists(p))))!
		}
		native_build_is_dir {
			p := v.pop_str()!
			v.push(v.enc_int(bool_i64(os.is_dir(p))))!
		}
		native_build_mkdir {
			p := v.pop_str()!
			os.mkdir_all(p) or { return error('build_mkdir: cannot create ${p}: ${err.msg()}') }
			v.push(v.enc_int(0))!
		}
		native_build_rm {
			p := v.pop_str()!
			if !os.exists(p) {
				v.push(v.enc_int(0))!
				return
			}
			if os.is_dir(p) {
				os.rmdir_all(p) or { return error('build_rm: cannot remove ${p}: ${err.msg()}') }
			} else {
				os.rm(p) or { return error('build_rm: cannot remove ${p}: ${err.msg()}') }
			}
			v.push(v.enc_int(1))!
		}
		native_build_copy {
			dst := v.pop_str()!
			src := v.pop_str()!
			if os.is_dir(src) {
				v.copy_tree(src, dst) or { return error('build_copy: ${err.msg()}') }
			} else {
				os.cp(src, dst, os.CopyParams{}) or {
					return error('build_copy: cannot copy ${src} -> ${dst}: ${err.msg()}')
				}
			}
			v.push(v.enc_int(0))!
		}
		native_build_glob {
			pat := v.pop_str()!
			files := os.glob(pat) or { return error('build_glob: ${err.msg()}') }
			mut arr := []i64{}
			for f in files {
				v.strings << f
				arr << v.mkstr(v.strings.len - 1)
			}
			v.arrays << arr
			v.push(v.mkarr(v.arrays.len - 1))!
		}
		native_build_ls {
			dir := v.pop_str()!
			entries := os.ls(dir) or { return error('build_ls: cannot read ${dir}: ${err.msg()}') }
			mut arr := []i64{}
			for f in entries {
				v.strings << f
				arr << v.mkstr(v.strings.len - 1)
			}
			v.arrays << arr
			v.push(v.mkarr(v.arrays.len - 1))!
		}
		native_build_base {
			p := v.pop_str()!
			v.push(v.alloc_str(os.base(p)))!
		}
		native_build_dir {
			p := v.pop_str()!
			v.push(v.alloc_str(os.dir(p)))!
		}
		native_build_join {
			b := v.pop_str()!
			a := v.pop_str()!
			v.push(v.alloc_str(os.join_path(a, b)))!
		}
		native_build_root {
			v.push(v.alloc_str(v.build_root))!
		}
		// -------------------------------------------------------------------
		// stdlib: JSON + string formatting
		native_json_encode {
			x := v.pop()!
			s := v.json_encode_value(x, 0) or { return error('json_encode: ${err.msg()}') }
			v.push(v.alloc_str(s))!
		}
		native_json_decode {
			s := v.pop_str()!
			val := v.json_parse(s) or { return error('json_decode: ${err.msg()}') }
			v.push(val)!
		}
		native_format {
			spec := v.pop_str()!
			x := v.pop()!
			s := v.format_value(x, spec) or { return error('format: ${err.msg()}') }
			v.push(v.alloc_str(s))!
		}
		native_replace {
			to := v.pop_str()!
			from := v.pop_str()!
			s := v.pop_str()!
			v.push(v.alloc_str(s.replace(from, to)))!
		}
		native_split_lines {
			s := v.pop_str()!
			mut arr := []i64{}
			for ln in s.split_into_lines() {
				v.strings << ln
				arr << v.mkstr(v.strings.len - 1)
			}
			v.arrays << arr
			v.push(v.mkarr(v.arrays.len - 1))!
		}
		native_pad {
			width := int(v.dec_int(v.pop()!))
			s := v.pop_str()!
			n := s.runes().len
			v.push(v.alloc_str(if n < width { s + ' '.repeat(width - n) } else { s }))!
		}
		native_pad_left {
			width := int(v.dec_int(v.pop()!))
			s := v.pop_str()!
			n := s.runes().len
			v.push(v.alloc_str(if n < width { ' '.repeat(width - n) + s } else { s }))!
		}
		native_repeat {
			n := int(v.dec_int(v.pop()!))
			s := v.pop_str()!
			if n < 0 {
				return error('repeat() expects a non-negative count')
			}
			v.push(v.alloc_str(s.repeat(n)))!
		}
		// -------------------------------------------------------------------
		// string builder — accumulate pieces and join once (linear, not
		// quadratic like repeated `+` concatenation)
		native_sb_new {
			v.builders << StrBuilder{}
			v.push(v.mkbuilder(v.builders.len - 1))!
		}
		native_sb_add {
			x := v.pop()!
			sb := v.pop()!
			if !v.is_builder(sb) || !v.valid_builder_handle(sb) {
				return error('sb_add expects a string builder as its first argument')
			}
			if v.is_str(x) && v.valid_handle(x) {
				v.builders[v.hand(sb)].parts << v.strings[v.hand(x)]
			} else {
				v.builders[v.hand(sb)].parts << v.val_str(x, 0)
			}
			v.push(sb)!
		}
		native_sb_str {
			sb := v.pop()!
			if !v.is_builder(sb) || !v.valid_builder_handle(sb) {
				return error('sb_str expects a string builder')
			}
			v.push(v.alloc_str(v.builders[v.hand(sb)].parts.join('')))!
		}
		native_sb_len {
			sb := v.pop()!
			if !v.is_builder(sb) || !v.valid_builder_handle(sb) {
				return error('sb_len expects a string builder')
			}
			mut n := 0
			for p in v.builders[v.hand(sb)].parts {
				n += p.len
			}
			v.push(v.enc_int(i64(n)))!
		}
		native_spawn {
			v.push(v.native_spawn(_argc)!)!
		}
		native_spawn_join {
			v.push(v.native_spawn_join()!)!
		}
		native_read_line {
			line := os.input_opt('') or { '' } // EOF → empty string
			v.push(v.alloc_str(line))!
		}
		native_input {
			prompt := v.pop_str()!
			eprint(prompt) // prompt on stderr so stdout stays clean for piping
			line := os.input_opt('') or { '' }
			v.push(v.alloc_str(line))!
		}
		native_flag_val {
			name := v.pop_str()!
			v.ensure_flags()
			v.push(v.alloc_str(v.flag_lookup(name)))!
		}
		native_flag_has {
			name := v.pop_str()!
			v.ensure_flags()
			v.push(v.enc_int(if v.flag_present_key(name) { 1 } else { 0 }))!
		}
		native_flag_positional {
			v.ensure_flags()
			mut arr := []i64{}
			for s in v.flags.positionals {
				v.strings << s
				arr << v.mkstr(v.strings.len - 1)
			}
			v.arrays << arr
			v.push(v.mkarr(v.arrays.len - 1))!
		}
		native_cwd {
			v.push(v.alloc_str(os.getwd()))!
		}
		native_json_pretty {
			x := v.pop()!
			s := v.json_pretty_value(x, 0) or { return error('json_pretty: ${err.msg()}') }
			v.push(v.alloc_str(s))!
		}
		// -------------------------------------------------------------------
		// HTTP client
		native_http_get {
			url := v.pop_str()!
			resp := http.get(url) or { return error('http_get: ${err.msg()}') }
			v.push_http_response(resp)!
		}
		native_http_post {
			data := v.pop_str()!
			url := v.pop_str()!
			resp := http.post(url, data) or { return error('http_post: ${err.msg()}') }
			v.push_http_response(resp)!
		}
		// -------------------------------------------------------------------
		// date/time
		native_now {
			v.push(v.enc_int(time.now().unix()))!
		}
		native_time_ms {
			v.push(v.enc_int(time.now().unix_milli()))!
		}
		native_format_time {
			spec := v.pop_str()!
			t := v.dec_int(v.pop()!)
			v.push(v.alloc_str(time.unix(t).custom_format(spec)))!
		}
		native_parse_time {
			s := v.pop_str()!
			t := time.parse(s) or { return error('parse_time: ${err.msg()}') }
			v.push(v.enc_int(t.unix()))!
		}
		native_weekday {
			t := v.dec_int(v.pop()!)
			v.push(v.alloc_str(time.unix(t).weekday_str()))!
		}
		// -------------------------------------------------------------------
		// regex — RE2-style patterns via V's regex module. Every call compiles
		// the pattern fresh; the VuurRaaf-level module can cache if it needs to.
		native_regex_match {
			s := v.pop_str()!
			pat := v.pop_str()!
			mut re := regex.regex_opt(pat) or { return error('regex: ${err.msg()}') }
			v.push(v.enc_int(bool_i64(re.matches_string(s))))!
		}
		native_regex_find_all {
			s := v.pop_str()!
			pat := v.pop_str()!
			mut re := regex.regex_opt(pat) or { return error('regex: ${err.msg()}') }
			matches := re.find_all_str(s)
			mut arr := []i64{}
			for m in matches {
				v.strings << m
				arr << v.mkstr(v.strings.len - 1)
			}
			v.arrays << arr
			v.push(v.mkarr(v.arrays.len - 1))!
		}
		native_regex_replace {
			repl := v.pop_str()!
			s := v.pop_str()!
			pat := v.pop_str()!
			mut re := regex.regex_opt(pat) or { return error('regex: ${err.msg()}') }
			v.push(v.alloc_str(re.replace(s, repl)))!
		}
		native_regex_split {
			s := v.pop_str()!
			pat := v.pop_str()!
			mut re := regex.regex_opt(pat) or { return error('regex: ${err.msg()}') }
			parts := re.split(s)
			mut arr := []i64{}
			for p in parts {
				v.strings << p
				arr << v.mkstr(v.strings.len - 1)
			}
			v.arrays << arr
			v.push(v.mkarr(v.arrays.len - 1))!
		}
		// -------------------------------------------------------------------
		// base64 + hashes
		native_base64_encode {
			s := v.pop_str()!
			v.push(v.alloc_str(base64.encode_str(s)))!
		}
		native_base64_decode {
			s := v.pop_str()!
			v.push(v.alloc_str(base64.decode_str(s)))!
		}
		native_sha256 {
			s := v.pop_str()!
			v.push(v.alloc_str(sha256.hexhash(s)))!
		}
		native_md5 {
			s := v.pop_str()!
			v.push(v.alloc_str(md5.hexhash(s)))!
		}
		native_csv_parse {
			s := v.pop_str()!
			mut r := csv.new_reader(s)
			// read() yields one row ([]string) at a time until EOF
			mut rows := [][]string{}
			for {
				row := r.read() or { break }
				if row.len == 0 {
					break
				}
				rows << row
			}
			mut outer := []i64{}
			for row in rows {
				mut inner := []i64{}
				for cell in row {
					v.strings << cell
					inner << v.mkstr(v.strings.len - 1)
				}
				v.arrays << inner
				outer << v.mkarr(v.arrays.len - 1)
			}
			v.arrays << outer
			v.push(v.mkarr(v.arrays.len - 1))!
		}
		// -------------------------------------------------------------------
		// extended HTTP: any method, custom headers (a {name: value} struct),
		// and a per-request timeout in milliseconds
		native_http_req {
			timeout_ms := int(v.dec_int(v.pop()!))
			headers_h := v.pop()!
			data := v.pop_str()!
			url := v.pop_str()!
			method := v.pop_str()!
			mut h := http.new_header()
			if v.is_struct(headers_h) && v.valid_struct_handle(headers_h) {
				for f in v.structs[v.hand(headers_h)].fields {
					if v.is_str(f.val) && v.valid_handle(f.val) {
						h.add_custom(f.name, v.strings[v.hand(f.val)]) or {}
					}
				}
			}
			m := match method.to_upper() {
				'GET' { http.Method.get }
				'POST' { http.Method.post }
				'PUT' { http.Method.put }
				'DELETE' { http.Method.delete }
				'PATCH' { http.Method.patch }
				'HEAD' { http.Method.head }
				else { return error('http_req: unsupported method "${method}"') }
			}
			resp := http.fetch(method: m, url: url, data: data, header: h,
				read_timeout: i64(timeout_ms) * time.millisecond) or {
				return error('http_req: ${err.msg()}')
			}
			v.push_http_response(resp)!
		}
		// -------------------------------------------------------------------
		// filesystem path helpers
		native_path_ext {
			p := v.pop_str()!
			v.push(v.alloc_str(os.file_ext(p)))!
		}
		native_path_abs {
			p := v.pop_str()!
			v.push(v.alloc_str(os.abs_path(p)))!
		}
		native_path_rel {
			base := v.pop_str()!
			p := v.pop_str()!
			v.push(v.alloc_str(v.rel_path(p, base)))!
		}
		// -------------------------------------------------------------------
		// process spawn with separate stdout/stderr pipes
		native_exec_full {
			cmd := v.pop_str()!
			mut code := 0
			mut out := ''
			mut errs := ''
			if os.user_os() == 'windows' {
				res := os.execute(cmd)
				code = res.exit_code
				out = res.output
			} else {
				mut p := os.new_process('sh')
				p.set_args(['-c', cmd])
				p.use_stdio_ctl = true
				p.run()
				p.wait()
				if p.err.len > 0 {
					return error('exec_full: ${p.err}')
				}
				code = p.code
				out = p.stdout_slurp()
				errs = p.stderr_slurp()
			}
			out_h := v.alloc_str(out)
			err_h := v.alloc_str(errs)
			mut fields := []Field{len: 3}
			fields[0] = Field{ name: 'code', val: v.enc_int(i64(code)) }
			fields[1] = Field{ name: 'stdout', val: out_h }
			fields[2] = Field{ name: 'stderr', val: err_h }
			v.structs << StructVal{ fields: fields, by_name: v.index_fields(fields) }
			v.push(v.mkstruct_handle(v.structs.len - 1))!
		}
		else {
			return error('unknown native builtin ${id}')
		}
	}
}

// rel_path computes a relative path from `base` to `p` (both absolutized),
// e.g. rel_path("/a/b/c.txt", "/a") == "b/c.txt". Used by os.rel().
fn (v Vm) rel_path(p string, base string) string {
	ap := os.abs_path(p).replace('\\', '/')
	ab := os.abs_path(base).replace('\\', '/')
	if ap == ab {
		return '.'
	}
	aparts := ap.split('/')
	bparts := ab.split('/')
	mut i := 0
	for i < aparts.len && i < bparts.len && aparts[i] == bparts[i] {
		i++
	}
	mut out := []string{}
	for _ in i..bparts.len {
		out << '..'
	}
	for j in i..aparts.len {
		out << aparts[j]
	}
	if out.len == 0 {
		return '.'
	}
	return out.join('/')
}

// push_http_response wraps an HTTP response as a {status, body} struct value
// so scripts can read res.status and res.body.
fn (mut v Vm) push_http_response(resp http.Response) ! {
	body_h := v.alloc_str(resp.body)
	mut fields := []Field{len: 2}
	fields[0] = Field{ name: 'status', val: v.enc_int(i64(resp.status_code)) }
	fields[1] = Field{ name: 'body', val: body_h }
	v.structs << StructVal{ fields: fields, by_name: v.index_fields(fields) }
	v.push(v.mkstruct_handle(v.structs.len - 1))!
}

// ---------------------------------------------------------------------------
// format() — a small printf-style formatter: %d %i %f %s %x %X %% with
// optional width, left-align (-), zero-padding (0), and precision (.N).
fn (mut v Vm) format_value(x i64, spec string) !string {
	if spec.len < 2 || spec[0] != `%` {
		return error('expected a printf-style spec like "%d" or "%.2f", got "${spec}"')
	}
	mut i := 1
	mut left := false
	mut zero := false
	if i < spec.len && spec[i] == `-` {
		left = true
		i++
	}
	if i < spec.len && spec[i] == `0` {
		zero = true
		i++
	}
	mut width := 0
	for i < spec.len && spec[i] >= `0` && spec[i] <= `9` {
		width = width * 10 + int(spec[i] - `0`)
		i++
	}
	mut prec := -1
	if i < spec.len && spec[i] == `.` {
		i++
		prec = 0
		for i < spec.len && spec[i] >= `0` && spec[i] <= `9` {
			prec = prec * 10 + int(spec[i] - `0`)
			i++
		}
	}
	if i >= spec.len {
		return error('incomplete format spec "${spec}"')
	}
	conv := spec[i]
	mut core := ''
	match conv {
		`d`, `i` {
			num := if v.is_float(x) { i64(v.fval(x)) } else { v.dec_int(x) }
			core = num.str()
		}
		`f` {
			f := if v.is_float(x) { v.fval(x) } else { f64(v.dec_int(x)) }
			core = v.format_fixed(f, if prec < 0 { 6 } else { prec })
		}
		`s` {
			core = v.val_str(x, 0)
			if prec >= 0 && core.len > prec {
				core = core[..prec]
			}
		}
		`x` {
			core = u64(v.dec_int(x)).hex()
		}
		`X` {
			core = u64(v.dec_int(x)).hex().to_upper()
		}
		`%` {
			return '%'
		}
		else {
			return error('unsupported conversion "%${conv.ascii_str()}" (supported: %d %i %f %s %x %X %%)')
		}
	}
	if core.len < width {
		n := width - core.len
		if left {
			core += ' '.repeat(n)
		} else if zero && core.starts_with('-') {
			core = '-' + '0'.repeat(n) + core[1..]
		} else if zero {
			core = '0'.repeat(n) + core
		} else {
			core = ' '.repeat(n) + core
		}
	}
	return core
}

// format_fixed renders an f64 in fixed-point notation with `prec` decimals
// (rounding), the way printf's %f does.
fn (mut v Vm) format_fixed(f f64, prec int) string {
	mut p := prec
	if p < 0 {
		p = 0
	}
	if p > 20 {
		p = 20
	}
	if math.is_nan(f) {
		return 'NaN'
	}
	if math.is_inf(f, 1) {
		return 'Inf'
	}
	if math.is_inf(f, -1) {
		return '-Inf'
	}
	neg := f < 0.0
	af := math.abs(f)
	// beyond ~15 digits a float no longer carries exact decimal places, so
	// fall back to the friendliest available rendering
	if af >= 1e15 {
		return fmt_float(f)
	}
	scale := math.pow(10.0, f64(p))
	r := math.round(af * scale)
	i := i64(r / scale)
	core := i.str()
	if p == 0 {
		return if neg { '-' + core } else { core }
	}
	d := i64(math.round(math.fmod(r, scale)))
	mut ds := d.str()
	if ds.len < p {
		ds = '0'.repeat(p - ds.len) + ds
	}
	return (if neg { '-' } else { '' }) + core + '.' + ds
}

// copy_tree recursively copies a directory tree (used by build_copy).
fn (mut v Vm) copy_tree(src string, dst string) ! {
	if !os.is_dir(src) {
		return error('${src} is not a directory')
	}
	os.mkdir_all(dst) or { return error('cannot create ${dst}: ${err.msg()}') }
	for entry in os.ls(src) or { return error('cannot read ${src}: ${err.msg()}') } {
		sp := os.join_path(src, entry)
		dp := os.join_path(dst, entry)
		if os.is_dir(sp) {
			v.copy_tree(sp, dp)!
		} else if os.is_file(sp) {
			os.cp(sp, dp, os.CopyParams{}) or { return error('cannot copy ${sp}: ${err.msg()}') }
		}
	}
}

// pop_str pops the top value and requires it to be a string.
fn (mut v Vm) pop_str() !string {
	x := v.pop()!
	if !v.is_str(x) || !v.valid_handle(x) {
		return error('expected a string argument')
	}
	return v.strings[v.hand(x)]
}

// --------------------------------------------------------------------------
// getopt-style flag parsing over the program's args.
//
// Flags are parsed once (lazily) into v.flags, and every flag / positional
// query reads from that shared result, so a token consumed as a flag value is
// never also reported as a positional. Supported forms: --name value,
// --name=value, boolean --name, single-letter short aliases (-n) derived from
// the long name's first character, and `--` to stop flag parsing. Negative
// numbers like -5 are treated as values, not flags. The first occurrence of a
// flag wins.
fn (mut v Vm) ensure_flags() {
	if v.flags.parsed {
		return
	}
	v.flags = FlagArgs{ parsed: true }
	mut i := 0
	for i < v.prog_args.len {
		a := v.prog_args[i]
		if a == '--' {
			// everything after -- is positional
			v.flags.positionals << v.prog_args[i + 1..]
			break
		}
		if !v.flag_token(a) {
			// positional, unless it was already consumed as a flag's value below
			v.flags.positionals << a
			i++
			continue
		}
		// a flag token. Only long flags (--name) consume a separate value token;
		// short flags (-v) are treated as boolean to avoid swallowing a following
		// positional (use -n=val or --name val for short aliases needing a value).
		name, val, has_inline := v.flag_key_val(a)
		long_flag := a.starts_with('--')
		if name !in v.flags.vals {
			if has_inline {
				v.flags.vals[name] = val
				i++
				continue
			}
			if long_flag && i + 1 < v.prog_args.len && !v.flag_token(v.prog_args[i + 1]) {
				v.flags.vals[name] = v.prog_args[i + 1]
				i += 2
			} else {
				v.flags.vals[name] = 'true'
				i++
			}
			continue
		}
		// duplicate flag: keep the first value, but still consume its value
		if long_flag && !has_inline && i + 1 < v.prog_args.len && !v.flag_token(v.prog_args[i + 1]) {
			i += 2
		} else {
			i++
		}
	}
}

// flag_token reports whether a is parsed as a flag rather than a value.
// flag_lookup returns the value of flag `name`, accepting its single-letter
// short alias as well. Returns '' when the flag was not passed.
fn (mut v Vm) flag_lookup(name string) string {
	if name in v.flags.vals {
		return v.flags.vals[name]
	}
	if name.len > 1 {
		short := name[..1]
		if short in v.flags.vals {
			return v.flags.vals[short]
		}
	}
	return ''
}

// flag_present_key reports whether flag `name` (or its short alias) was passed
// at all, regardless of its value.
fn (mut v Vm) flag_present_key(name string) bool {
	if name in v.flags.vals {
		return true
	}
	if name.len > 1 {
		return name[..1] in v.flags.vals
	}
	return false
}

fn (mut v Vm) flag_token(a string) bool {
	if a == '-' {
		return false
	}
	if !a.starts_with('-') {
		return false
	}
	// a negative number (-5, -3.14) is a value, not a flag
	if a.len > 1 && a[1] >= `0` && a[1] <= `9` {
		return false
	}
	return true
}

// flag_key_val splits a flag token into its canonical (dash-stripped) name and
// any inline value. Returns (name, value, has_inline_value).
fn (mut v Vm) flag_key_val(a string) (string, string, bool) {
	raw := a.trim_left('-') // strip leading dashes
	mut eq := -1
	for i in 0..raw.len {
		if raw[i] == `=` {
			eq = i
			break
		}
	}
	if eq >= 0 {
		return raw[..eq], raw[eq + 1..], true
	}
	return raw, '', false
}

// type_name returns the type label of a tagged value.
fn (mut v Vm) type_name(x i64) string {
	if v.is_str(x) {
		return 'string'
	}
	if v.is_float(x) {
		return 'float'
	}
	if v.is_none(x) {
		return 'none'
	}
	if v.is_closure(x) {
		return 'closure'
	}
	if v.is_arr(x) {
		return 'array'
	}
	if v.is_struct(x) {
		return 'struct'
	}
	return 'int'
}

// type_info_value reflects a value into a struct for generic/duck-typed code:
// { kind, is_number, is_int, is_float, is_string, is_array, is_struct,
//   is_none, is_closure, len, fields } where `fields` is the array of field
// names (structs) and `len` is the element/character count for arrays/strings.
fn (mut v Vm) type_info_value(x i64) i64 {
	kind := v.type_name(x)
	is_int := v.is_int(x)
	is_float := v.is_float(x)
	is_string := v.is_str(x) && v.valid_handle(x)
	is_array := v.is_arr(x) && v.valid_arr_handle(x)
	is_struct := v.is_struct(x) && v.valid_struct_handle(x)
	is_none := v.is_none(x)
	is_closure := v.is_closure(x) && v.valid_closure_handle(x)
	is_number := is_int || is_float
	// len: array -> element count; string -> character count; struct -> field count
	mut length := 0
	if is_array {
		length = v.arrays[v.hand(x)].len
	} else if is_string {
		length = v.strings[v.hand(x)].runes().len
	} else if is_struct {
		length = v.structs[v.hand(x)].fields.len
	}
	// fields: array of struct field names (empty otherwise)
	mut names := []i64{}
	if is_struct {
		for f in v.structs[v.hand(x)].fields {
			v.strings << f.name
			names << v.mkstr(v.strings.len - 1)
		}
	}
	v.arrays << names
	field_h := v.mkarr(v.arrays.len - 1)
	mut fields := []Field{}
	fields << Field{ name: 'kind', val: v.alloc_str(kind) }
	fields << Field{ name: 'is_number', val: v.enc_int(if is_number { 1 } else { 0 }) }
	fields << Field{ name: 'is_int', val: v.enc_int(if is_int { 1 } else { 0 }) }
	fields << Field{ name: 'is_float', val: v.enc_int(if is_float { 1 } else { 0 }) }
	fields << Field{ name: 'is_string', val: v.enc_int(if is_string { 1 } else { 0 }) }
	fields << Field{ name: 'is_array', val: v.enc_int(if is_array { 1 } else { 0 }) }
	fields << Field{ name: 'is_struct', val: v.enc_int(if is_struct { 1 } else { 0 }) }
	fields << Field{ name: 'is_none', val: v.enc_int(if is_none { 1 } else { 0 }) }
	fields << Field{ name: 'is_closure', val: v.enc_int(if is_closure { 1 } else { 0 }) }
	fields << Field{ name: 'len', val: v.enc_int(i64(length)) }
	fields << Field{ name: 'fields', val: field_h }
	fields << Field{ name: 'contents', val: x }
	v.structs << StructVal{ fields: fields, by_name: v.index_fields(fields) }
	return v.mkstruct_handle(v.structs.len - 1)
}

// range_value builds the array [a, a+1, ..., b) as ints.
fn (mut v Vm) range_value(a i64, b i64) i64 {
	start := v.dec_int(a)
	end := v.dec_int(b)
	mut arr := []i64{}
	if start <= end {
		for i := start; i < end; i++ {
			arr << v.enc_int(i)
		}
	} else {
		for i := start; i > end; i-- {
			arr << v.enc_int(i)
		}
	}
	v.arrays << arr
	return v.mkarr(v.arrays.len - 1)
}

// str_method dispatches a string method call. The receiver was pushed before
// the arguments, so it is the first argument from the native builtin's point
// of view; delegating keeps the behavior identical to the free-function forms.
fn (mut v Vm) str_method(name string, argc int) ! {
	bid := match name {
		'to_upper' { native_upper }
		'to_lower' { native_lower }
		'trim' { native_trim }
		'contains' { native_contains }
		'starts_with' { native_starts_with }
		'ends_with' { native_ends_with }
		'split' { native_split }
		'index_of' { native_index_of }
		'to_int' { native_int }
		'to_float' { native_float }
		'replace' { native_replace }
		'split_lines' { native_split_lines }
		'pad' { native_pad }
		'pad_left' { native_pad_left }
		'repeat' { native_repeat }
		else { -1 }
	}
	if bid >= 0 {
		// native builtins pop the first argument (the receiver) last
		v.native(bid, argc + 1)!
		return
	}
	if name == 'len' {
		h := v.pop()!
		if !v.is_str(h) || !v.valid_handle(h) {
			return error('len() on a non-string value')
		}
		v.push(v.enc_int(i64(v.strings[v.hand(h)].runes().len)))!
		return
	}
	return error('unknown string method "${name}"')
}

// merge_sort sorts a[lo..hi) ascending by numeric value, using tmp as the
// scratch buffer (must be at least hi long). It is stable: equal elements
// keep their relative order.
fn (mut v Vm) merge_sort(mut a []i64, mut tmp []i64, lo int, hi int) {
	if hi - lo <= 1 {
		return
	}
	mid := lo + (hi - lo) / 2
	v.merge_sort(mut a, mut tmp, lo, mid)
	v.merge_sort(mut a, mut tmp, mid, hi)
	mut i := lo
	mut j := mid
	mut k := lo
	for i < mid && j < hi {
		if !v.num_gt(a[i], a[j]) {
			// a[i] <= a[j]: take from the left half (equal -> left, so stable)
			tmp[k] = a[i]
			i++
		} else {
			tmp[k] = a[j]
			j++
		}
		k++
	}
	for i < mid {
		tmp[k] = a[i]
		i++
		k++
	}
	for j < hi {
		tmp[k] = a[j]
		j++
		k++
	}
	for x in lo..hi {
		a[x] = tmp[x]
	}
}

// num_gt compares two values by their numeric value (int or float).
fn (mut v Vm) num_gt(x i64, y i64) bool {
	if v.is_float(x) || v.is_float(y) {
		return v.to_f64(x) > v.to_f64(y)
	}
	return v.dec_int(x) > v.dec_int(y)
}
