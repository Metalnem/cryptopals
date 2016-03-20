%% Challenge 6 - Break repeating-key XOR
%% http://cryptopals.com/sets/1/challenges/6/

-module(c06).
-export([partition/2, decrypt_repeating_key_xor/1, run/0]).

hamming_distance(<<C1, Rest1/binary>>, <<C2, Rest2/binary>>) ->
	hamming_weight(<<(C1 bxor C2)>>) + hamming_distance(Rest1, Rest2);

hamming_distance(<<>>, <<>>) -> 0.

hamming_weight(<<>>) -> 0;
hamming_weight(<<0:1, Rest/bitstring>>) -> hamming_weight(Rest);
hamming_weight(<<1:1, Rest/bitstring>>) -> 1 + hamming_weight(Rest).

pairwise([H | T], F) -> [F(H, X) || X <- T] ++ pairwise(T, F);
pairwise([], _) -> [].

key_size(Ciphertext) ->
	{KeySize, _} =
		lists:foldl(fun(KeySize, {_, Acc} = State) ->
			Blocks = lists:map(fun(Index) -> binary:part(Ciphertext, Index * KeySize, KeySize) end, lists:seq(0, 5)),
			Distances = pairwise(Blocks, fun(B1, B2) -> hamming_distance(B1, B2) end),
			NormalizedDistance = lists:sum(Distances) / KeySize,
			case NormalizedDistance < Acc of
				true -> {KeySize, NormalizedDistance};
				false -> State
			end
		end, {undefined, 1.0e10}, lists:seq(2, 60)),
	KeySize.

partition([], _) -> [];

partition(L, N) ->
	case length(L) >= N of
		true -> {L1, L2} = lists:split(N, L), [L1 | partition(L2, N)];
		false -> [L]
	end.

transpose([[] | _]) -> [];

transpose(M) ->
	Heads = lists:filtermap(fun([H | _]) -> {true, H};
  		([]) -> false end, M),
	Tails = lists:filtermap(fun([_ | T]) -> {true, T};
  		([]) -> false end, M),
  	[Heads | transpose(Tails)].

split(Ciphertext, KeySize) ->
	L = binary:bin_to_list(Ciphertext),
	Blocks = partition(L, KeySize),
	transpose(Blocks).

decrypt_repeating_key_xor(Ciphertext) ->
	KeySize = key_size(Ciphertext),
	Blocks = split(Ciphertext, KeySize),
	Decrypted = lists:map(fun(Block) ->
		Bin = binary:list_to_bin(Block),
		Result = c03:decrypt_single_char_xor(Bin),
		binary:bin_to_list(Result)
	end, Blocks),
	lists:flatten(transpose(Decrypted)).

run() ->
	37 = hamming_distance(<<"this is a test">>, <<"wokka wokka!!!">>),
	Base64Lines = c04:read_lines("c06.txt"),
	EncryptedLines = lists:map(fun base64:decode/1, Base64Lines),
	Ciphertext = binary:list_to_bin(EncryptedLines),
	Result = decrypt_repeating_key_xor(Ciphertext),
	io:fwrite("~s", [Result]).
