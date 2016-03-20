%% Challenge 4 - Detect single-character XOR
%% http://cryptopals.com/sets/1/challenges/4/

-module(c04).
-export([read_lines/1, detect_single_char_xor/1, run/0]).

read_lines(Path) ->
	{ok, Contents} = file:read_file(Path),
    binary:split(Contents, [<<"\r\n">>, <<"\n">>], [global]).

detect_single_char_xor([H | T], {_, Value} = State) ->
	S = c01:hex_to_string(H),
	Decrypted = c03:decrypt_single_char_xor(S),
	NewValue = c03:evaluate(Decrypted),
	case NewValue > Value of
		true -> detect_single_char_xor(T, {Decrypted, NewValue});
		false -> detect_single_char_xor(T, State)
	end;

detect_single_char_xor([], {Acc, _}) -> Acc.
detect_single_char_xor(Lines) -> detect_single_char_xor(Lines, {undefined, 0}).

run() ->
	Encrypted = read_lines("c04.txt"),
	<<"Now that the party is jumping\n">> = detect_single_char_xor(Encrypted),
	ok.
