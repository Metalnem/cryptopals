%% Challenge 8 - Detect AES in ECB mode
%% http://cryptopals.com/sets/1/challenges/8/

-module(c08).
-export([run/0]).

number_of_repeated_blocks(S) ->
	L = binary:bin_to_list(S),
	Blocks = c06:partition(L, 16),
	Unique = sets:from_list(Blocks),
	length(Blocks) - sets:size(Unique).

run() ->
	HexLines = c04:read_lines("c08.txt"),
	{Line, _} = lists:foldl(fun(HexLine, {_, Acc} = State) ->
		Line = c01:hex_to_string(HexLine),
		N = number_of_repeated_blocks(Line),
		case N > Acc of
			true -> {HexLine, N};
			false -> State
		end end, {undefined, -1}, HexLines),
	Line.
