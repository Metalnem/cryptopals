%% Challenge 23 - Clone an MT19937 RNG from its output
%% http://cryptopals.com/sets/3/challenges/23/

-module(c23).
-export([run/0, test/1, untemper/1]).
-define(MASK1, 16#9d2c5680).
-define(MASK2, 16#efc60000).
-define(SIZE, 624).

temper(X) ->
	X1 = temper1(X),
	X2 = temper2(X1),
	X3 = temper3(X2),
	X4 = temper4(X3),
	X4.

temper1(X) -> X bxor (X bsr 11).
temper2(X) -> X bxor ((X bsl 7) band ?MASK1).
temper3(X) -> X bxor ((X bsl 15) band ?MASK2).
temper4(X) -> X bxor (X bsr 18).

untemper(Y) ->
	X3 = untemper4(Y),
	X2 = untemper3(X3),
	X1 = untemper2(X2),
	X = untemper1(X1),
	X.

untemper1(X) ->
	X1 = temper1(X),
 	X2 = X1 bxor (X1 bsr 22),
 	X2.

untemper2(X) ->
	C1 = (?MASK1 bsl 7) band ?MASK1,
	C2 = (C1 bsl 14) band C1,
	X1 = temper2(X),
	X2 = X1 bxor ((X1 bsl 14) band C1),
	X3 = X2 bxor ((X2 bsl 28) band C2),
	X3.

untemper3(X) ->
	C1 = (?MASK2 bsl 15) band ?MASK2,
	X1 = temper3(X),
	X2 = X1 bxor ((X1 bsl 30) band C1),
	X2.

untemper4(X) -> temper4(X).

test(16#100000000) -> ok;

test(X) ->
	Result = untemper(temper(X)), 
	case Result of
		X -> test(X + 1);
		_ -> {error, Result}
	end.

run() ->
	mt:start_link(),
	Counter = lists:seq(1, ?SIZE),
	Values = lists:map(fun(_) -> mt:next_int() end, Counter),
	Seed = lists:map(fun untemper/1, Values),
	mt:seed_array(Seed),
	Values = lists:map(fun(_) -> mt:next_int() end, Counter),
	mt:stop(),
	ok.
