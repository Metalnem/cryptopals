-module(mt).
-behaviour(gen_server).
-export([start_link/0, start_link/1, stop/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
-export([next_int/0, seed/1, seed_array/1]).
-define(SIZE, 624).

init(_, Acc) when length(Acc) =:= ?SIZE -> lists:reverse(Acc);

init(Index, Acc) ->
	Previous = hd(Acc),
	Next = 16#ffffffff band (16#6c078965 * (Previous bxor (Previous bsr 30)) + Index),
	init(Index + 1, [Next | Acc]).

generate_numbers(State) ->
	Result = generate_numbers(0, array:from_list(State)),
	array:to_list(Result).

generate_numbers(Index, State) when Index =:= ?SIZE -> State;
	
generate_numbers(Index, State) ->
	X = (array:get(Index, State) band 16#80000000)
		+ (array:get((Index + 1) rem ?SIZE, State) band 16#7fffffff),
	Y = array:get((Index + 397) rem ?SIZE, State) bxor (X bsr 1),
	NewState = array:set(Index, Y, State),
	case X rem 2 of
		0 -> generate_numbers(Index + 1, NewState);
		_ -> generate_numbers(Index + 1, array:set(Index, Y bxor 16#9908b0df, NewState))
	end.

random([], State) ->
	NewState = generate_numbers(State),
	random(NewState, NewState);

random([Head | Tail], State) ->
	X1 = Head,
	X2 = X1 bxor (X1 bsr 11),
	X3 = X2 bxor ((X2 bsl 7) band 16#9d2c5680),
	X4 = X3 bxor ((X3 bsl 15) band 16#efc60000),
	X5 = X4 bxor (X4 bsr 18),
	{X5, Tail, State}.

start_link() -> start_link(0).
start_link(Seed) -> gen_server:start_link({local, ?MODULE}, ?MODULE, Seed, []).

stop() -> gen_server:cast(?MODULE, stop).
init(Seed) -> {ok, {[], init(1, [Seed])}}.

handle_call(random, _From, {Current, Initial}) ->
	{Result, NewCurrent, NewInitial} = random(Current, Initial),
	{reply, Result, {NewCurrent, NewInitial}}.

handle_cast({seed, Seed}, _State) -> {noreply, {[], init(1, [Seed])}};
handle_cast({seed_array, SeedArray}, _State) when length(SeedArray) =:= ?SIZE -> {noreply, {SeedArray, SeedArray}};
handle_cast(stop, State) -> {stop, normal, State}.

handle_info(_Info, State) -> {noreply, State}.
terminate(_Reason, _State) -> ok.
code_change(_OldVsn, State, _Extra) -> {ok, State}.

next_int() -> gen_server:call(?MODULE, random).
seed(Seed) -> gen_server:cast(?MODULE, {seed, Seed}).
seed_array(SeedArray) when length(SeedArray) =:= ?SIZE -> gen_server:cast(?MODULE, {seed_array, SeedArray}).
