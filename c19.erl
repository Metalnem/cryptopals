%% Challenge 19 - Break fixed-nonce CTR mode using substitions
%% http://cryptopals.com/sets/3/challenges/19/

-module(c19).
-export([run/0]).
-define(HALF_BLOCK_SIZE, 8).

plaintexts() -> [
	<<"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==">>,
	<<"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=">>,
	<<"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==">>,
	<<"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=">>,
	<<"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk">>,
	<<"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==">>,
	<<"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=">>,
	<<"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==">>,
	<<"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=">>,
	<<"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl">>,
	<<"VG8gcGxlYXNlIGEgY29tcGFuaW9u">>,
	<<"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==">>,
	<<"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=">>,
	<<"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==">>,
	<<"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=">>,
	<<"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=">>,
	<<"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==">>,
	<<"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==">>,
	<<"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==">>,
	<<"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==">>,
	<<"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==">>,
	<<"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==">>,
	<<"U2hlIHJvZGUgdG8gaGFycmllcnM/">>,
	<<"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=">>,
	<<"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=">>,
	<<"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=">>,
	<<"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=">>,
	<<"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==">>,
	<<"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==">>,
	<<"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=">>,
	<<"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==">>,
	<<"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu">>,
	<<"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=">>,
	<<"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs">>,
	<<"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=">>,
	<<"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0">>,
	<<"SW4gdGhlIGNhc3VhbCBjb21lZHk7">>,
	<<"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=">>,
	<<"VHJhbnNmb3JtZWQgdXR0ZXJseTo=">>,
	<<"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=">>
].

run() ->
	Key = c11:random_key(),
	Nonce = <<0:?HALF_BLOCK_SIZE/little-unit:8>>,
	
	Ciphertexts = lists:map(fun(Plaintext) ->
		S = base64:decode(Plaintext),
		aes:aes_ctr_encrypt(Key, Nonce, S)
	end, plaintexts()),

	Length = lists:foldl(fun(Ciphertext, Acc) ->
		min(Acc, byte_size(Ciphertext))
	end, 1000, Ciphertexts),

	Truncated = lists:map(fun(Ciphertext) ->
		<<Result:Length/binary, _/binary>> = Ciphertext,
		Result
	end, Ciphertexts),

	Decrypted = c06:decrypt_repeating_key_xor(list_to_binary(Truncated)),
	Blocks = c06:partition(Decrypted, Length),
	lists:map(fun(Plaintext) -> io:fwrite("~s~n", [Plaintext]) end, Blocks),
	ok.
