%% Challenge 21 - Implement the MT19937 Mersenne Twister RNG
%% http://cryptopals.com/sets/3/challenges/21/

-module(c21).
-export([run/0]).

run() ->
	{ok, Content} = file:read_file("mt.txt"),
	S = binary_to_list(Content),
	Expected = lists:map(fun(X) -> {Result, []} = string:to_integer(X), Result end, string:tokens(S, " \r\n")),
	mt:start_link(1),
	Actual = lists:map(fun(_) -> mt:next_int() end, lists:seq(1, 10000)),
	mt:stop(),
	Actual = Expected,
	ok.
