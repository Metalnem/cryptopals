-module(aes).
-export([pkcs7_pad/2, pkcs7_unpad/2]).
-export([aes128_block_encrypt/2, aes128_block_decrypt/2]).
-export([aes128_ecb_encrypt/2, aes128_ecb_decrypt/2]).
-export([aes128_cbc_encrypt/3, aes128_cbc_decrypt/3]).
-export([aes_ctr_encrypt/3]).
-define(BLOCK_SIZE, 16).
-define(HALF_BLOCK_SIZE, 8).

xor_buffers(<<C1, Rest1/binary>>, <<C2, Rest2/binary>>) ->
	C = C1 bxor C2,
	Result = xor_buffers(Rest1, Rest2),
	<<C, Result/binary>>;

xor_buffers(<<>>, <<>>) -> <<>>.

xor_buffers_prefix(<<C1, Rest1/binary>>, <<C2, Rest2/binary>>) ->
	<<(C1 bxor C2), (xor_buffers_prefix(Rest1, Rest2))/binary>>;

xor_buffers_prefix(<<>>, _) -> <<>>;
xor_buffers_prefix(_, <<>>) -> <<>>.

pkcs7_pad(Bin, BlockSize) when BlockSize >= 0, BlockSize =< 128 ->
	Size = byte_size(Bin),
	PaddingSize = BlockSize - Size rem BlockSize,
	Padding = binary:copy(<<PaddingSize>>, PaddingSize),
	<<Bin/binary, Padding/binary>>.

pkcs7_unpad(Bin, BlockSize) when BlockSize >= 0, BlockSize =< 128 ->
	Size = byte_size(Bin),

	case (Size > 0) and (Size rem BlockSize =:= 0) of
		true ->
			Size1 = Size - BlockSize,
			Size2 = BlockSize - 1,
			<<Part1:Size1/binary, Part2:Size2/binary, LastByte>> = Bin,
			
			case (LastByte =< BlockSize) and (LastByte > 0) of
				true ->
					ActualPadding = binary:part(Part2, {BlockSize - 1, 1 - LastByte}),
					ExpectedPadding = binary:copy(<<LastByte>>, LastByte - 1),

					case ActualPadding =:= ExpectedPadding of
						true -> <<Part1/binary, (binary:part(Part2, 0, BlockSize - LastByte))/binary>>;
						false -> throw(padding_error)
					end;
				false ->
				 	throw(padding_error)
			end;
		false ->
			throw(padding_error)
	end.

aes128_block_encrypt(<<_:16/binary>> = Plaintext, <<_:16/binary>> = Key) ->
	crypto:block_encrypt(aes_cbc128, Key, <<0:128>>, Plaintext).

aes128_block_decrypt(<<_:16/binary>> = Ciphertext, <<_:16/binary>> = Key) ->
	crypto:block_decrypt(aes_cbc128, Key, <<0:128>>, Ciphertext).

aes128_ecb_encrypt(<<Key:16/binary>>, <<_/binary>> = Plaintext) ->
	Input = pkcs7_pad(Plaintext, 16),
	aes128_ecb_encrypt_impl(Key, Input).

aes128_ecb_encrypt_impl(_, <<>>) -> <<>>;

aes128_ecb_encrypt_impl(Key, Plaintext) ->
	PlaintextBlock = binary:part(Plaintext, 0, 16),
	CiphertextBlock = aes128_block_encrypt(PlaintextBlock, Key),
	Rest = aes128_ecb_encrypt_impl(Key, binary:part(Plaintext, 16, byte_size(Plaintext) - 16)),
	<<CiphertextBlock/binary, Rest/binary>>.

aes128_ecb_decrypt(<<Key:16/binary>>, <<_/binary>> = Ciphertext) ->
	Output = aes128_ecb_decrypt_impl(Key, Ciphertext),
	pkcs7_unpad(Output, 16).

aes128_ecb_decrypt_impl(_, <<>>) -> <<>>;

aes128_ecb_decrypt_impl(Key, Ciphertext) ->
	CiphertextBlock = binary:part(Ciphertext, 0, 16),
	PlaintextBlock = aes128_block_decrypt(CiphertextBlock, Key),
	Rest = aes128_ecb_decrypt_impl(Key, binary:part(Ciphertext, 16, byte_size(Ciphertext) - 16)),
	<<PlaintextBlock/binary, Rest/binary>>.

aes128_cbc_encrypt(<<Key:16/binary>>, <<Iv:16/binary>>, <<_/binary>> = Plaintext) ->
	Input = pkcs7_pad(Plaintext, 16),
	aes128_cbc_encrypt_impl(Key, Iv, Input, <<>>).

aes128_cbc_encrypt_impl(_, _, <<>>, Acc) -> Acc;

aes128_cbc_encrypt_impl(Key, PreviousCiphertextBlock, Plaintext, Acc) ->
	PlaintextBlock = binary:part(Plaintext, 0, 16),
	CiphertextBlock = aes128_block_encrypt(xor_buffers(PlaintextBlock, PreviousCiphertextBlock), Key),
	Result = <<Acc/binary, CiphertextBlock/binary>>,
	aes128_cbc_encrypt_impl(Key, CiphertextBlock, binary:part(Plaintext, 16, byte_size(Plaintext) - 16), Result).

aes128_cbc_decrypt(<<Key:16/binary>>, <<Iv:16/binary>>, <<_/binary>> = Ciphertext) ->
	Output = aes128_cbc_decrypt_impl(Key, Iv, Ciphertext, <<>>),
	pkcs7_unpad(Output, 16).

aes128_cbc_decrypt_impl(_, _, <<>>, Acc) -> Acc;

aes128_cbc_decrypt_impl(Key, PreviousCiphertextBlock, Ciphertext, Acc) ->
	CiphertextBlock = binary:part(Ciphertext, 0, 16),
	PlaintextBlock = xor_buffers(aes128_block_decrypt(CiphertextBlock, Key), PreviousCiphertextBlock),
	Result = <<Acc/binary, PlaintextBlock/binary>>,
	aes128_cbc_decrypt_impl(Key, CiphertextBlock, binary:part(Ciphertext, 16, byte_size(Ciphertext) - 16), Result).

aes_ctr_encrypt(<<Key:?BLOCK_SIZE/binary>>, <<Nonce:?HALF_BLOCK_SIZE/binary>>, <<_/binary>> = Plaintext) ->
	aes_ctr_encrypt_impl(Key, Nonce, Plaintext, 0).

aes_ctr_encrypt_impl(Key, Nonce, <<Block:?BLOCK_SIZE/binary, Rest/binary>>, Counter) ->
	EncryptedBlock = encrypt_block(Key, Nonce, Block, Counter),
	Result = aes_ctr_encrypt_impl(Key, Nonce, Rest, Counter + 1),
	<<EncryptedBlock/binary, Result/binary>>;

aes_ctr_encrypt_impl(Key, Nonce, Plaintext, Counter) ->
	encrypt_block(Key, Nonce, Plaintext, Counter).

encrypt_block(Key, Nonce, Block, Counter) ->
	KeyBlock = <<Nonce/binary, Counter:?HALF_BLOCK_SIZE/little-unit:8>>,
	EncryptedKey = aes:aes128_block_encrypt(KeyBlock, Key),
	xor_buffers_prefix(Block, EncryptedKey).
