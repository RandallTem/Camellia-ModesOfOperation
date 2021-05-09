import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

public class CTR_ACPKM {

    private long[] createIV() {
        long[] iv = new long[2];
        iv[0] = new Random().nextLong();
        return iv;
    }

    private byte[] longArrayToByte(long[] longs){
        byte[] bytes = new byte[8 * longs.length];
        for (int i = longs.length-1; i >= 0; i--) {
            for (int j = 7; j >= 0; j--) {
                bytes[i * 8 + j] = (byte)longs[i];
                longs[i] >>>= 8;
            }
        }
        return bytes;
    }

    private byte[][] longToByte(long D1, long D2){
        byte[][] bytes = new byte[2][8];
        for (int i = 7; i >=0 ; i--){
            bytes[0][i]= (byte)D1;
            bytes[1][i] = (byte)D2;
            D1 >>>= 8;
            D2 >>>= 8;
        }
        return bytes;
    }

    private int countExtraBytes(long[] res){
        long mask = 0xFFL;
        int counter = 0, index = 1;
        while ((res[index] & mask) == 0) {
            counter++;
            mask <<=8;
            if (counter == 8) {
                mask = 0xFFL;
                index--;
            }
        }
        return counter;
    }

    private long[] ACPKM(long[] subkeys, int key_length) {
        final long[] D1 = {0x8081828384858687L, 0x88898A8B8C8D8E8FL};
        final long[] D2 = {0x9091929394959697L, 0x98999A9B9C9D9E9FL};
        Camellia camellia = new Camellia();
        long[] temp1, temp2;
        byte[] new_key_bytes;
        if (key_length == 128) {
            long[] key128 = camellia.cryptBlock(D1[0], D1[1], subkeys);
            new_key_bytes = longArrayToByte(key128);
        } else if(key_length == 192) {
            temp1 = camellia.cryptBlock(D1[0], D1[1], subkeys);
            temp2 = camellia.cryptBlock(D2[0], D2[1], subkeys);
            long[] key192 = {temp1[0], temp1[1], temp2[0]};
            new_key_bytes = longArrayToByte(key192);
        } else {
            temp1 = camellia.cryptBlock(D1[0], D1[1], subkeys);
            temp2 = camellia.cryptBlock(D2[0], D2[1], subkeys);
            long[] key256 = {temp1[0], temp1[1], temp2[0], temp2[1]};
            new_key_bytes = longArrayToByte(key256);
        }
        long[] new_subkeys = camellia.keySchedule(new_key_bytes);
        return new_subkeys;
    }

    public void Encrypt(String path, String key, int R) {
        try {
            Camellia camellia = new Camellia();
            BufferedInputStream reader = new BufferedInputStream(new FileInputStream(path), 16);
            BufferedOutputStream writer = new BufferedOutputStream(
                    new FileOutputStream(path + ".crptd"));
            byte[] bytes = new byte[16];
            long[] plaintext = new long[2];
            long[] ciphertext;
            int i, key_update_counter = 0;
            int key_size;
            if (key.length() <= 16)
                key_size = 128;
            else if (key.length() > 16 && key.length() <= 24)
                key_size = 192;
            else
                key_size = 256;
            long[] subkeys = camellia.keySchedule(key);
            long[] ctr = createIV();
            byte[][] ciphertext_bytes = longToByte(ctr[0], ctr[1]);
            writer.write(ciphertext_bytes[0]);
            writer.write(ciphertext_bytes[1]);
            while ((i = (reader.read(bytes))) == 16) {
                if (key_update_counter == R) {
                    subkeys = ACPKM(subkeys, key_size);
                    key_update_counter = 0;
                }
                plaintext[0] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,0,8)).getLong();
                plaintext[1] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,8,16)).getLong();
                ciphertext = camellia.cryptBlock(ctr[0], ctr[1]++, subkeys);
                ciphertext[0] ^= plaintext[0];
                ciphertext[1] ^= plaintext[1];
                ciphertext_bytes = longToByte(ciphertext[0], ciphertext[1]);
                writer.write(ciphertext_bytes[0]);
                writer.write(ciphertext_bytes[1]);
                writer.flush();
                key_update_counter++;
            }
            if (i > 0 && i < 8){
                plaintext[0] = 0;
                plaintext[1] = 0;
                for (int j = 0; j < i; j++){
                    plaintext[0] <<= 8;
                    plaintext[0] += bytes[j];
                }
                plaintext[0] <<= 64-(i*8);
            } else if (i >= 8){
                plaintext[0] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,0,8)).getLong();
                plaintext[1] = 0;
                for (int j = 8; j < i; j++){
                    plaintext[1] <<= 8;
                    plaintext[1] += bytes[j];
                }
                plaintext[1] <<= 64-((i-8)*8);
            }
            if (i != -1) {
                if (key_update_counter == R)
                    subkeys = ACPKM(subkeys, key_size);
                ciphertext = camellia.cryptBlock(ctr[0], ctr[1]++, subkeys);
                ciphertext[0] ^= plaintext[0];
                ciphertext[1] ^= plaintext[1];
                ciphertext_bytes = longToByte(ciphertext[0], ciphertext[1]);
                writer.write(ciphertext_bytes[0]);
                writer.write(ciphertext_bytes[1]);
                writer.flush();
            }
            reader.close();
            writer.close();
        } catch (Exception e) {
            System.out.println("Error occurred");
            System.out.println(e);
            return;
        }
    }

    public void Decrypt(String path, String key, int R) {
        try {
            Camellia camellia = new Camellia();
            BufferedInputStream reader = new BufferedInputStream(new FileInputStream(path), 16);
            BufferedOutputStream writer = new BufferedOutputStream(
                    new FileOutputStream(path.substring(0, path.lastIndexOf("."))));
            byte[] bytes = new byte[16];
            reader.read(bytes);
            long[] ctr = {
                    ByteBuffer.wrap(Arrays.copyOfRange(bytes, 0, 8)).getLong(),
                    ByteBuffer.wrap(Arrays.copyOfRange(bytes, 8, 16)).getLong()
            };
            long[] ciphertext = new long[2];
            long[] plaintext;
            int i, key_update_counter = 0;
            int key_size;
            if (key.length() <= 16)
                key_size = 128;
            else if (key.length() > 16 && key.length() <= 24)
                key_size = 192;
            else
                key_size = 256;
            long[] subkeys = camellia.keySchedule(key);
            byte[][] plaintext_bytes;
            while ((i = (reader.read(bytes))) == 16) {
                if (key_update_counter == R) {
                    subkeys = ACPKM(subkeys, key_size);
                    key_update_counter = 0;
                }
                ciphertext[0] = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 0, 8)).getLong();
                ciphertext[1] = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 8, 16)).getLong();
                plaintext = camellia.cryptBlock(ctr[0], ctr[1]++, subkeys);
                plaintext[0] ^= ciphertext[0];
                plaintext[1] ^= ciphertext[1];
                plaintext_bytes = longToByte(plaintext[0], plaintext[1]);
                if (reader.available() == 0) {
                    int counter = countExtraBytes(plaintext);
                    if (counter <= 8) {
                        writer.write(plaintext_bytes[0]);
                        writer.write(plaintext_bytes[1], 0, 8-counter);
                    } else {
                        writer.write(plaintext_bytes[0], 0, 16-counter);
                    }
                    writer.flush();
                } else {
                    writer.write(plaintext_bytes[0]);
                    writer.write(plaintext_bytes[1]);
                    writer.flush();
                }
                key_update_counter++;
            }
            reader.close();
            writer.close();
        } catch (Exception e) {
            System.out.println("Error occurred");
            System.out.println(e);
            return;
        }
    }
}
