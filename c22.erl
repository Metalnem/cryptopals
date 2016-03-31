%% Challenge 22 - Crack an MT19937 seed
%% http://cryptopals.com/sets/3/challenges/22/

-module(c22).
-export([run/0, timestamp/0]).

timestamp() ->
	{Mega, Secs, _} = now(),
	Mega * 1000000 + Secs.

first_int(Seed) ->
	mt:seed(Seed),
	Result = mt:next_int(),
	Result.

random() ->
	timer:sleep(1000 * (5 + random:uniform(10))),
	Timestamp = timestamp(),
	Result = first_int(Timestamp),
	timer:sleep(1000 * (5 + random:uniform(10))),
	{Timestamp, Result}.

crack_seed(X) -> crack_seed(timestamp(), X).

crack_seed(Timestamp, X) ->
	case first_int(Timestamp) =:= X of
		true -> Timestamp;
		false -> crack_seed(Timestamp - 1, X)
	end.

run() ->
	mt:start_link(),
	{Timestamp, Result} = random(),
	Seed = crack_seed(Result),
	mt:stop(),
	Timestamp = Seed,
	ok.
