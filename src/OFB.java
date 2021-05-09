import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

public class OFB {
    private long[] createIV() {
        long[] iv = new long[2];
        iv[0] = new Random().nextLong();
        iv[1] = new Random().nextLong();
        return iv;
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
        int counter = 0, index = 1;
        long mask = 0xFFL, comp = 0x80L;
        for (int i = 0; i < 16; i++){
            if (i == 8) {
                mask = 0xFFL;
                comp = 0x80L;
                index = 0;
            }
            if ((res[index] & mask) == 0) {
                counter++;
                mask <<= 8;
                comp <<= 8;
            } else if ((res[index] & mask) == comp) {
                return ++counter;
            } else {
                return 0;
            }
        }
        return 0;
    }

    public void Encrypt(String path, String key) {
        try {
            Camellia camellia = new Camellia();
            BufferedInputStream reader = new BufferedInputStream(new FileInputStream(path), 16);
            BufferedOutputStream writer = new BufferedOutputStream(
                    new FileOutputStream(path+".crptd"));
            byte[] bytes = new byte[16];
            long[] plaintext = new long[2];
            int i;
            long[] subkeys = camellia.keySchedule(key);
            long[] ciphertext = createIV();
            byte[][] ciphertext_bytes;
            byte[][] iv_bytes = longToByte(ciphertext[0], ciphertext[1]);
            writer.write(iv_bytes[0]);
            writer.write(iv_bytes[1]);
            while ((i = (reader.read(bytes))) == 16) {
                plaintext[0] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,0,8)).getLong();
                plaintext[1] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,8,16)).getLong();
                ciphertext = camellia.cryptBlock(ciphertext[0], ciphertext[1], subkeys);
                plaintext[0] ^= ciphertext[0];
                plaintext[1] ^= ciphertext[1];
                ciphertext_bytes = longToByte(plaintext[0], plaintext[1]);
                writer.write(ciphertext_bytes[0]);
                writer.write(ciphertext_bytes[1]);
                writer.flush();
            }
            if (i > 0 && i < 8){
                plaintext[0] = 0;
                plaintext[1] = 0;
                for (int j = 0; j < i; j++){
                    plaintext[0] <<= 8;
                    plaintext[0] += bytes[j];
                }
                plaintext[0] <<= 1;
                plaintext[0] += 1;
                plaintext[0] <<= 64-(i*8+1);
            } else if (i >= 8){
                plaintext[0] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,0,8)).getLong();
                plaintext[1] = 0;
                for (int j = 8; j < i; j++){
                    plaintext[1] <<= 8;
                    plaintext[1] += bytes[j];
                }
                plaintext[1] <<= 1;
                plaintext[1] += 1;
                plaintext[1] <<= 64-((i-8)*8+1);
            }
            if (i != -1) {
                ciphertext = camellia.cryptBlock(ciphertext[0], ciphertext[1], subkeys);
                plaintext[0] ^= ciphertext[0];
                plaintext[1] ^= ciphertext[1];
                ciphertext_bytes = longToByte(plaintext[0], plaintext[1]);
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

    public void Decrypt(String path, String key) {
        try {
            Camellia camellia = new Camellia();
            BufferedInputStream reader = new BufferedInputStream(new FileInputStream(path), 16);
            BufferedOutputStream writer = new BufferedOutputStream(
                    new FileOutputStream(path.substring(0, path.lastIndexOf("."))));
            byte[] bytes = new byte[16];
            long[] ciphertext = new long[2];
            long[] plaintext = new long[2];
            reader.read(bytes);
            long[] ex_ciphertext = {
                    ByteBuffer.wrap(Arrays.copyOfRange(bytes, 0, 8)).getLong(),
                    ByteBuffer.wrap(Arrays.copyOfRange(bytes, 8, 16)).getLong()
            };
            int i;
            long[] subkeys = camellia.keySchedule(key);
            while ((i = (reader.read(bytes))) == 16) {
                ciphertext[0] = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 0, 8)).getLong();
                ciphertext[1] = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 8, 16)).getLong();
                ex_ciphertext = camellia.cryptBlock(ex_ciphertext[0], ex_ciphertext[1], subkeys);
                plaintext[0] = ex_ciphertext[0] ^ ciphertext[0];
                plaintext[1] = ex_ciphertext[1] ^ ciphertext[1];
                byte[][] plaintext_bytes = longToByte(plaintext[0], plaintext[1]);
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
