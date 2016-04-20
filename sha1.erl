-module(sha1).
-export([run/0, digest/1, digest/3]).
-define(MASK, 16#ffffffff).

digest(Message) ->
	H0 = 16#67452301,
	H1 = 16#efcdab89,
	H2 = 16#98badcfe,
	H3 = 16#10325476,
	H4 = 16#c3d2e1f0,
	Length = bit_size(Message),
	Result = process(pad(Message, Length), {H0, H1, H2, H3, H4}),
	list_to_binary(string:right(integer_to_list(Result, 16), 40, $0)).

digest(Message, PrevState, PrevLength) ->
	Length = PrevLength + bit_size(Message),
	Result = process(pad(Message, Length), PrevState),
	list_to_binary(string:right(integer_to_list(Result, 16), 40, $0)).

pad(Message, Length) ->
	Size = bit_size(Message),
	Rem = 512 - (Size + 8) rem 512,
	PaddingSize =
		case Rem < 64 of
			true -> Rem + 448;
			false -> Rem - 64
		end,
	<<Message/binary, 128, 0:PaddingSize, Length:8/big-unit:8>>.

process(<<>>, State) -> process_final_state(State);
process(<<Chunk:64/binary, Rest/binary>>, State) -> process(Rest, process_chunk(Chunk, State)).

process_chunk(Chunk, {H0, H1, H2, H3, H4} = State) ->
	Words = extend_chunk(Chunk),
	{A, B, C, D, E} = main_loop(0, Words, State),
	{add(H0, A), add(H1, B), add(H2, C), add(H3, D), add(H4, E)}.

extend_chunk(Chunk) ->
	Words = to_array(Chunk),
	extend_array(16, Words).

extend_array(80, A) -> A;

extend_array(I, A) ->
	Temp = array:get(I - 3, A) bxor array:get(I - 8, A) bxor array:get(I - 14, A) bxor array:get(I - 16, A),
	extend_array(I + 1, array:set(I, left_rotate(Temp, 1), A)).

to_array(Bin) -> to_array(Bin, 0, array:new()).

to_array(<<>>, _I, A) -> A;
to_array(<<X:32, Rest/binary>>, I, A) -> to_array(Rest, I + 1, array:set(I, X, A)).

main_loop(80, _Words, State) -> State;

main_loop(I, Words, {A, B, C, D, E}) ->
	{F, K} = main_loop_helper(I, {B, C, D}),
	Temp = (left_rotate(A, 5) + F + E + K + array:get(I, Words)) band ?MASK,
	main_loop(I + 1, Words, {Temp, A, left_rotate(B, 30), C, D}).

main_loop_helper(I, {B, C, D}) when I < 20 ->
	F = (B band C) bor ((bnot B) band D),
	K = 16#5a827999,
	{F, K};

main_loop_helper(I, {B, C, D}) when I < 40 ->
	F = B bxor C bxor D,
	K = 16#6ed9eba1,
	{F, K};

main_loop_helper(I, {B, C, D}) when I < 60 ->
	F = (B band C) bor (B band D) bor (C band D),
	K = 16#8f1bbcdc,
	{F, K};

main_loop_helper(I, {B, C, D}) when I < 80 ->
	F = B bxor C bxor D,
	K = 16#CA62C1D6,
	{F, K}.

process_final_state({H0, H1, H2, H3, H4}) ->
	(H0 bsl 128) bor (H1 bsl 96) bor (H2 bsl 64) bor (H3 bsl 32) bor H4.

add(X, Y) -> (X + Y) band ?MASK.
left_rotate(X, N) when N < 32 -> (X bsl N) band ?MASK bor (X bsr (32 - N)).

run() ->
	<<"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709">> = digest(<<>>),
	<<"2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12">> = digest(<<"The quick brown fox jumps over the lazy dog">>),
	<<"DE9F2C7FD25E1B3AFAD3E85A0BD17D9B100DB4B3">> = digest(<<"The quick brown fox jumps over the lazy cog">>),
	<<"CF23DF2207D99A74FBE169E3EBA035E633B65D94">> = digest(<<"sha1 this string">>),
	ok.
