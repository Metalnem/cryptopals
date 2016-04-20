%% Challenge 28 - Implement a SHA-1 keyed MAC
%% http://cryptopals.com/sets/4/challenges/28/

-module(c28).
-export([run/0, sha1mac/2]).

sha1mac(Key, Message) -> sha1:digest(<<Key/binary, Message/binary>>).

run() ->
	<<"1ADF20C8B9D700EE2B6798D26510B2791C451442">> = sha1mac(<<"YELLOW SUBMARINE">>, <<"Monty Python">>),
	ok.
