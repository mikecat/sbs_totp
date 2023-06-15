"use strict";

window.addEventListener("DOMContentLoaded", function() {
	// IDつきの要素を取得
	const nodes = {};
	document.querySelectorAll("*").forEach(function(element) {
		const id = element.getAttribute("id");
		if (id !== null) nodes[id] = element;
	});
	// Base32用の文字
	const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

	// 非負整数を文字列に変換する。最低桁数と進数を指定できる。
	const intToStr = function(value, minDigits, radix) {
		if ((typeof minDigits) === "undefined") minDigits = 0;
		if ((typeof radix) === "undefined") radix = 10;
		let res = value.toString(radix);
		while (res.length < minDigits) res = "0" + res;
		return res;
	};

	// Uint8Array同士を結合する
	const appendUint8Array = function(a, b) {
		const result = new Uint8Array(a.length + b.length);
		result.set(a, 0);
		result.set(b, a.length);
		return result;
	};

	// datetime-localのvalueのエンコードとデコード
	const decodeDateTime = function(value) {
		const values = value.split(/[-T:]/);
		if (values.length === 5) values.push("0");
		if (values.length !== 6) return null;
		const year = parseInt(values[0]);
		const month = parseInt(values[1]);
		const day = parseInt(values[2]);
		const hour = parseInt(values[3]);
		const minutes = parseInt(values[4]);
		const seconds = parseInt(values[5]);
		if (isNaN(year) || isNaN(month) || isNaN(day) || isNaN(hour) || isNaN(minutes) || isNaN(seconds)) {
			return null;
		}
		const d = new Date(year, month - 1, day, hour, minutes, seconds);
		if (0 <= year && year <= 99) {
			// 1900～1999年と認識されるので、0～99年に直す
			d.setDate(1); // 月の設定時に繰り上がりでずれるのを防ぐ
			d.setFullYear(year);
			d.setMonth(month - 1);
			d.setDate(day);
		}
		return d;
	};
	const encodeDateTime = function(date) {
		const res = intToStr(date.getFullYear(), 4) + "-" +
			intToStr(date.getMonth() + 1, 2) + "-" + 
			intToStr(date.getDate(), 2) + "T" +
			intToStr(date.getHours(), 2) + ":" +
			intToStr(date.getMinutes(), 2) + ":" +
			intToStr(date.getSeconds(), 2);
		if (date.getFullYear() > 9999) {
			return "+" + res;
		} else {
			return res;
		}
	};

	// 指定した要素の子を、与えた要素だけにする
	const setChild = function(target, child) {
		while (target.firstChild !== null) {
			target.removeChild(target.firstChild);
		}
		target.appendChild(child);
	};

	// バイト列 (配列的なやつ) をHTML要素に変換する
	const bytesToElement = function(bytes) {
		const elem = document.createElement("span");
		elem.setAttribute("class", "bytes");
		let data = "";
		for (let i = 0; i < bytes.length; i++) {
			if (i > 0) {
				if (i % 32 === 0) {
					elem.appendChild(document.createTextNode(data));
					elem.appendChild(document.createElement("br"));
					data = "";
				} else {
					data += " ";
					if (i % 4 === 0) data += " ";
				}
			}
			data += intToStr(bytes[i] & 0xff, 2, 16);
		}
		elem.appendChild(document.createTextNode(data));
		return elem;
	};

	// TOTPのT0が設定されていなければ初期値を設定する
	if (nodes.input_TOTP_T0.value === "") {
		nodes.input_TOTP_T0.value = encodeDateTime(new Date(0));
	}

	// SHA-1の計算を行なう
	const sha1 = (function() {
		const add = function(x, y) {
			return (x + y) >>> 0;
		};
		const S = function(n, X) {
			return ((X << n) | (X >>> (32 - n))) >>> 0;
		};
		const f = [
			function(B, C, D) {
				return ((B & C) | (~B & D)) >>> 0;
			},
			function(B, C, D) {
				return (B ^ C ^ D) >>> 0;
			},
			function(B, C, D) {
				return ((B & C) | (B & D) | (C & D)) >>> 0;
			},
			function(B, C, D) {
				return (B ^ C ^ D) >>> 0;
			},
		];
		const K = [
			0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6,
		];
		return function(bytes) {
			const padSize = 64 - (bytes.length + 8) % 64;
			const padBuffer = new ArrayBuffer(padSize + 8);
			const padView = new DataView(padBuffer);
			padView.setUint8(0, 0x80);
			padView.setUint32(padSize, (bytes.length / (1 << 29)) >>> 0, false);
			padView.setUint32(padSize + 4, (bytes.length & 0x1fffffff) * 8, false);
			const data = appendUint8Array(bytes, new Uint8Array(padBuffer));
			const dataView = new DataView(data.buffer, data.byteOffset, data.byteLength);
			const H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
			for (let i = 0; i < data.length; i += 64) {
				const W = [];
				for (let j = 0; j < 16; j++) {
					W.push(dataView.getUint32(i + 4 * j, false));
				}
				for (let t = 16; t < 80; t++) {
					W.push(S(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]));
				}
				let A = H[0], B = H[1], C = H[2], D = H[3], E = H[4];
				for (let t = 0; t < 80; t++) {
					const TEMP = (S(5, A) + f[(t / 20) >>> 0](B, C, D) + E + W[t] + K[(t / 20) >>> 0]) >>> 0;
					E = D;
					D = C;
					C = S(30, B);
					B = A;
					A = TEMP;
				}
				H[0] = add(H[0], A);
				H[1] = add(H[1], B);
				H[2] = add(H[2], C);
				H[3] = add(H[3], D);
				H[4] = add(H[4], E);
			}
			const hashBuffer = new ArrayBuffer(20);
			const hashView = new DataView(hashBuffer);
			for (let i = 0; i < 5; i++) {
				hashView.setUint32(4 * i, H[i], false);
			}
			return new Uint8Array(hashBuffer);
		};
	})();

	// HOTP/TOTPの処理を行う
	const updateHOTP = function() {
		// TOTPのTを計算する
		const TOTP_T = (function() {
			const T0 = decodeDateTime(nodes.input_TOTP_T0.value);
			const X = parseInt(nodes.input_TOTP_X.value);
			const currentTime = decodeDateTime(nodes.input_TOTP_time.value);
			if (T0 === null || isNaN(T0.getTime()) || isNaN(X) || X <= 0 ||
			currentTime === null || isNaN(currentTime.getTime())) {
				return null;
			}
			return Math.floor(Math.floor((currentTime - T0) / 1000) / X);
		})();
		status_TOTP_T.textContent = TOTP_T === null ? "invalid" : TOTP_T;
		// コードの種類を表示し、HOTPのCの値を取得する
		const HOTP_C_BigInt = (function() {
			if (nodes.input_TOTP.checked) {
				nodes.result_type.textContent = "TOTP";
				return TOTP_T === null ? null : BigInt(TOTP_T);
			} else {
				nodes.result_type.textContent = "HOTP";
				try {
					return BigInt(nodes.input_HOTP_C.value);
				} catch (e) {
					return null;
				}
			}
		})();
		// コードの種類を設定する
		nodes.result_type.textContent = nodes.input_TOTP.checked ? "TOTP" : "HOTP";
		// 表示をエラーモードにする
		nodes.error_area.classList.remove("hidden-element");
		nodes.internal_values_area.classList.add("hidden-element");
		// 桁数を取得する
		const numDigits = parseInt(nodes.input_Digit.value);
		if (isNaN(numDigits)) {
			nodes.error_area.textContent = "The value of Digit is invalid.";
			return;
		}
		if (numDigits <= 0) {
			nodes.error_area.textContent = "The value of Digit must be positive.";
			return;
		}
		if (numDigits > 32) {
			nodes.error_area.textContent = "The value of Digit is too large. (maximum 32)";
			return;
		}
		// 取得した桁数を用いてコードを仮設定する
		nodes.result_area.textContent = (function() {
			let data = "";
			for (let i = 0; i < numDigits; i++) data += "*";
			return data;
		})();
		// KをBase32デコードする
		const K_decoded = (function(encoded) {
			const res = [];
			let byteBuffer = 0, bufferedBits = 0;
			for (let i = 0; i < encoded.length; i++) {
				const idx = base32chars.indexOf(encoded.charAt(i));
				if (idx < 0) return null;
				byteBuffer = (byteBuffer << 5) | idx;
				bufferedBits += 5;
				while (bufferedBits >= 8) {
					res.push((byteBuffer >> (bufferedBits - 8)) & 0xff);
					bufferedBits -= 8;
				}
				byteBuffer &= 0xff;
			}
			return new Uint8Array(res);
		})(nodes.input_K.value.toUpperCase());
		if (K_decoded === null) {
			nodes.error_area.textContent = "The value of K is invalid.";
			return;
		}
		setChild(nodes.internal_K_decode, bytesToElement(K_decoded));
		// Cの値を取得する
		if (HOTP_C_BigInt === null) {
			nodes.error_area.textContent = "The value of C is invalid.";
			return;
		}
		const C_bytes = (function(value) {
			const data = [];
			for (let i = 0; i < 8; i++) {
				data.unshift(Number(value & 0xffn));
				value >>= 8n;
			}
			if (value !== 0n && value !== -1n) return null; // オーバーフロー
			return new Uint8Array(data);
		})(HOTP_C_BigInt);
		if (C_bytes === null) {
			nodes.error_area.textContent = "The value of C doesn't fit in 64-bit.";
			return;
		}
		setChild(nodes.internal_C_bytes, bytesToElement(C_bytes));

		// HMAC
		const hmac_K_raw = (function() {
			if (K_decoded.length <= 64) {
				nodes.hmac_key_hash.classList.add("hidden-element");
				return K_decoded;
			} else {
				nodes.hmac_key_hash.classList.remove("hidden-element");
				return sha1(K_decoded);
			}
		})();
		setChild(nodes.hmac_key, bytesToElement(hmac_K_raw));
		const hmac_K_ipad = new Uint8Array((function() {
			const res = [];
			for (let i = 0; i < 64; i++) {
				res.push((i < hmac_K_raw.length ? hmac_K_raw[i] :0) ^ 0x36);
			}
			return res;
		})());
		setChild(nodes.hmac_K_ipad, bytesToElement(hmac_K_ipad));
		const hmac_K_ipad_text = appendUint8Array(hmac_K_ipad, C_bytes);
		setChild(nodes.hmac_K_ipad_text, bytesToElement(hmac_K_ipad_text));
		const hmac_K_opad = new Uint8Array((function() {
			const res = [];
			for (let i = 0; i < 64; i++) {
				res.push((i < hmac_K_raw.length ? hmac_K_raw[i] :0) ^ 0x5c);
			}
			return res;
		})());
		setChild(nodes.hmac_K_opad, bytesToElement(hmac_K_opad));
		const hmac_H_K_ipad_text = sha1(hmac_K_ipad_text);
		setChild(nodes.hmac_H_K_ipad_text, bytesToElement(hmac_H_K_ipad_text));
		const hmac_before_hash = appendUint8Array(hmac_K_opad, hmac_H_K_ipad_text);
		setChild(nodes.hmac_before_hash, bytesToElement(hmac_before_hash));
		const hmac_result = sha1(hmac_before_hash);
		setChild(nodes.hmac_result, bytesToElement(hmac_result));
		setChild(nodes.internal_HS, bytesToElement(hmac_result));

		// DT(HS)
		const dt_offset = hmac_result[19] & 0xf;
		nodes.dt_OffsetBits.textContent = dt_offset.toString(16);
		nodes.dt_Offset.textContent = dt_offset.toString(10);
		const dt_p = hmac_result.slice(dt_offset, dt_offset + 4);
		setChild(nodes.dt_P, bytesToElement(dt_p));
		const dt_p_last = new Uint8Array(dt_p);
		dt_p_last[0] &= 0x7f;
		setChild(nodes.dt_P_last, bytesToElement(dt_p_last));
		setChild(nodes.internal_DT_HS, bytesToElement(dt_p_last));

		const Snum = new DataView(dt_p_last.buffer, dt_p_last.byteOffset, dt_p_last.byteLength).getUint32(0, false);
		nodes.internal_Snum.textContent = Snum;

		const pow_Digit = (function(num) {
			let r = 1;
			for (let i = 0; i < num; i++) r *= 10;
			return r;
		})(numDigits > 10 ? 10 : numDigits); // 32ビットの整数は十進数で高々10桁
		const D = Snum % pow_Digit;
		nodes.internal_D.textContent = D;

		nodes.result_area.textContent = intToStr(D, numDigits);

		// 通常モードにする
		nodes.error_area.classList.add("hidden-element");
		nodes.internal_values_area.classList.remove("hidden-element");
	};
	nodes.input_K.addEventListener("input", updateHOTP);
	nodes.input_Digit.addEventListener("input", updateHOTP);
	nodes.input_HOTP.addEventListener("input", updateHOTP);
	nodes.input_HOTP_C.addEventListener("input", updateHOTP);
	nodes.input_TOTP.addEventListener("input", updateHOTP);
	nodes.input_TOTP_X.addEventListener("input", updateHOTP);
	nodes.input_TOTP_time.addEventListener("input", updateHOTP);

	// TOTP用の現在時刻を更新する
	const updateRealtime = function() {
		if (nodes.input_TOTP_realtime.checked) {
			const currentDate = encodeDateTime(new Date());
			if (currentDate !== nodes.input_TOTP_time.value) {
				nodes.input_TOTP_time.value = currentDate;
				updateHOTP();
			}
			requestAnimationFrame(updateRealtime);
		}
	};
	nodes.input_TOTP_realtime.addEventListener("change", updateRealtime);
	updateRealtime();
	updateHOTP();
});
