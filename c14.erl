%% Challenge 14 - Byte-at-a-time ECB decryption (Harder)
%% http://cryptopals.com/sets/2/challenges/14/

-module(c14).
-export([run/0, decrypt/1]).
-define(BLOCK_SIZE, 16).

encrypt(Prefix, Plaintext, Key) ->
	Base64Encoded = <<"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
		"YnkK">>,
	Secret = base64:decode(Base64Encoded),
	Input = <<Prefix/binary, Plaintext/binary, Secret/binary>>,
	aes:aes128_ecb_encrypt(Key, Input).

decrypt(F) ->
	PaddingSize = determine_padding_size(F),
	SecretPosition = determine_secret_position(F),

	PrefixPaddingSize = ?BLOCK_SIZE - (SecretPosition rem ?BLOCK_SIZE),
	PrefixPadding = <<0:PrefixPaddingSize/unit:8>>,

	KnownBytesSize = ?BLOCK_SIZE - 1,
	KnownBytes = <<0:KnownBytesSize/unit:8>>,

	SecretSize = byte_size(F(<<>>)) - PaddingSize - SecretPosition,
	Position = (SecretPosition div ?BLOCK_SIZE + 1) * ?BLOCK_SIZE,
	
	<<_:KnownBytesSize/unit:8, Result/binary>> = decrypt_impl(F, 0, SecretSize, Position, KnownBytes, PrefixPadding),
	Result.

decrypt_impl(_, Size, Size, _, KnownBytes, _) -> KnownBytes;

decrypt_impl(F, Index, Size, Position, KnownBytes, PrefixPadding) ->
	Prefix1 = binary:copy(<<0>>, ?BLOCK_SIZE - (Index rem ?BLOCK_SIZE) - 1),
	Prefix2 = binary:part(KnownBytes, byte_size(KnownBytes) - ?BLOCK_SIZE + 1, ?BLOCK_SIZE - 1),

	Chars = lists:seq(0, 255),
	ActualSize = byte_size(KnownBytes) - ?BLOCK_SIZE + 1,
	BlockPosition = Position + ActualSize - ActualSize rem ?BLOCK_SIZE,

	Encrypted = F(<<PrefixPadding/binary, Prefix1/binary>>),
	CurrentBlock = binary:part(Encrypted, BlockPosition, ?BLOCK_SIZE),

	Candidates = lists:map(fun(C) ->
		Result = F(<<PrefixPadding/binary, Prefix2/binary, C>>),
		{C, binary:part(Result, Position, ?BLOCK_SIZE)}
	end, Chars),
	
	{C, _ } = lists:keyfind(CurrentBlock, 2, Candidates),
	decrypt_impl(F, Index + 1, Size, Position, <<KnownBytes/binary, C>>, PrefixPadding).

determine_padding_size(F) -> determine_padding_size_impl(F, <<>>, byte_size(F(<<>>))).

determine_padding_size_impl(F, PrevInput, PrevSize) ->
	Input = <<0, PrevInput/binary>>,
	Result = F(Input),
	Size = byte_size(Result),
	case Size > PrevSize of
		true -> byte_size(Input);
		false -> determine_padding_size_impl(F, Input, Size)
	end.

determine_secret_position(F) ->
	Input = <<(binary:copy(<<1>>, 2 * ?BLOCK_SIZE))/binary>>,
	determine_secret_position_impl(F, Input).

determine_secret_position_impl(F, Input) ->
	Encrypted = F(<<0, Input/binary, 0>>),
	Blocks = c06:partition(binary:bin_to_list(Encrypted), ?BLOCK_SIZE),
	
	{Position, _, _} =
		lists:foldl(fun(Block, {Position, Index, PrevBlock}) ->
			case Block =:= PrevBlock of
				true -> {Index - 1, Index + 1, Block};
				false -> {Position, Index + 1, Block}
			end
		end, {undefined, 0, undefined}, Blocks),

	case Position of
		undefined -> determine_secret_position_impl(F, <<Input/binary, 1>>);
		_ -> Position * ?BLOCK_SIZE - byte_size(Input) + 2 * ?BLOCK_SIZE - 1
	end.

run() ->
	Prefix = crypto:rand_bytes(crypto:rand_uniform(0, 48)),
	Key = c11:random_key(),
	F = fun(Plaintext) -> encrypt(Prefix, Plaintext, Key) end,
	Result = decrypt(F),
	io:fwrite("~s", [Result]),
	ok.
