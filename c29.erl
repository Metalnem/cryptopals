%% Challenge 29 - Break a SHA-1 keyed MAC using length extension
%% http://cryptopals.com/sets/4/challenges/29/

-module(c29).
-export([run/0]).

random_key() ->
	Length = crypto:rand_uniform(1, 256),
	crypto:rand_bytes(Length).

extract_state(<<S0:8/binary, S1:8/binary, S2:8/binary, S3:8/binary, S4:8/binary>>) ->
	H0 = list_to_integer(binary_to_list(S0), 16),
	H1 = list_to_integer(binary_to_list(S1), 16),
	H2 = list_to_integer(binary_to_list(S2), 16),
	H3 = list_to_integer(binary_to_list(S3), 16),
	H4 = list_to_integer(binary_to_list(S4), 16),
	{H0, H1, H2, H3, H4}.

forge(Sign, Validate) ->
	Message = <<"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon">>,
	Suffix = <<";admin=true">>,
	PrevState = extract_state(Sign(Message)),
	forge(Message, Suffix, PrevState, 1, Validate).

forge(Message, Suffix, PrevState, KeyLength, Validate) ->
	PrevLength = KeyLength + byte_size(Message),
	<<_:PrevLength/binary, Padding/binary>> = sha1:pad(<<0:KeyLength/unit:8, Message/binary>>, 8 * PrevLength),
	ForgedMessage = <<Message/binary, Padding/binary, Suffix/binary>>,
	ForgedMac = sha1:digest(Suffix, PrevState, 8 * PrevLength + bit_size(Padding)),
	case Validate(ForgedMac, ForgedMessage) of
		true -> {ForgedMessage, ForgedMac};
		false -> forge(Message, Suffix, PrevState, KeyLength + 1, Validate)
	end.

run() ->
	Key = random_key(),
	Sign = fun(Message) -> c28:sha1mac(Key, Message) end,
	Validate = fun(Mac, Message) -> c28:sha1mac(Key, Message) =:= Mac end,
	{ForgedMessage, ForgedMac} = forge(Sign, Validate),
	ForgedMac = Sign(ForgedMessage),
	ok.
