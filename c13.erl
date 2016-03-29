%% Challenge 13 - ECB cut-and-paste
%% http://cryptopals.com/sets/2/challenges/13/

-module(c13).
-export([run/0, decode/1, encode/1, profile_for/1, make_admin/1]).

decode(S) ->
	KeyValuePairs = binary:split(S, <<"&">>, [global]),
	lists:foldr(fun(KeyValuePair, Acc) ->
		[Key, Value] = binary:split(KeyValuePair, <<"=">>),
		[{Key, Value} | Acc]
	end, [], KeyValuePairs).

encode(L) ->
	lists:foldl(fun({Key, Value}, Acc) ->
		KeyValuePair = <<Key/binary, "=", Value/binary>>,
		case byte_size(Acc) of
			0 -> KeyValuePair;
			_ -> <<Acc/binary, "&", KeyValuePair/binary>>
		end
	end, <<>>, L).

escape(S) -> binary:replace(S, [<<"&">>, <<"=">>], <<>>, [global]).
profile_for(Email) -> encode([ {<<"email">>, escape(Email)}, {<<"uid">>, <<"10">>}, {<<"role">>, <<"user">>}]).

make_admin(F) ->
	Admin = <<"admin">>,
	BlockSize = 16,

	AdminPadded = aes:pkcs7_pad(Admin, BlockSize),
	<<_:BlockSize/binary, AdminBlock:BlockSize/binary, _/binary>> = F(<<"a@test.com", AdminPadded/binary>>),

	Encrypted = F(<<"abcd@test.com">>),
	Result = binary:part(Encrypted, 0, byte_size(Encrypted) - BlockSize),
	<<Result/binary, AdminBlock/binary>>.

run() ->
	Key = c11:random_key(),
	F = fun(Email) -> aes:aes128_ecb_encrypt(Key, profile_for(Email)) end,
	Profile = make_admin(F),
	Decrypted = aes:aes128_ecb_decrypt(Key, Profile),
	<<"email=abcd@test.com&uid=10&role=admin">> = binary:part(Decrypted, 0, byte_size(Decrypted)),
	ok.
