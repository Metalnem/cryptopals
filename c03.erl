%% Challenge 3 - Single-byte XOR cipher
%% http://cryptopals.com/sets/1/challenges/3/

-module(c03).
-export([evaluate/1, decrypt_single_char_xor/1, run/0]).

evaluate(<<>>) -> 0;
evaluate(<<C, Rest/binary>>) -> evaluate_impl(C) + evaluate(Rest).

evaluate_impl(C) when C =:= $E; C =:= $T; C =:= $A; C =:= $O; C =:= $I; C =:= $N -> 5;
evaluate_impl(C) when C =:= $e; C =:= $t; C =:= $a; C =:= $o; C =:= $i; C =:= $n -> 5;
evaluate_impl(C) when C =:= $S; C =:= $H; C =:= $R; C =:= $D; C =:= $L; C =:= $U -> 5;
evaluate_impl(C) when C =:= $s; C =:= $h; C =:= $r; C =:= $d; C =:= $l; C =:= $u -> 5;
evaluate_impl(C) when C =:= 32; C >= $A, C =< $Z; C >= $a, C =< $z; C >= $0, C =< $9 -> 2;
evaluate_impl(C) when C =:= 10; C =:= 13; C > 32, C < 128 -> -5;
evaluate_impl(_) -> -1.0e5.

decrypt_single_char_xor(S) ->
	Chars = lists:seq(0, 255),
	Keys = lists:map(fun(C) -> list_to_binary(string:chars(C, byte_size(S))) end, Chars),
	Decrypted = lists:map(fun(Key) -> c02:xor_buffers(S, Key) end, Keys),
	{Result, _} = lists:foldl(fun(X, {_, Value} = State) ->
		NewValue = evaluate(X),
		case NewValue > Value of
			true -> {X, NewValue};
			false -> State
		end end, {undefined, -1.0e10}, Decrypted),
	Result.

run() ->
	Hex = <<"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736">>,
	Encrypted = c01:hex_to_string(Hex),
	<<"Cooking MC's like a pound of bacon">> = decrypt_single_char_xor(Encrypted),
	ok.
