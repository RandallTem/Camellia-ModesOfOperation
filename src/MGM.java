import java.io.*;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;
import java.util.Vector;

public class MGM {

    private long[] createNonce() {
        long[] nonce = new long[2];
        nonce[0] = new Random().nextLong();
        nonce[0] = (nonce[0] & 0x8000000000000000L) != 0 ? nonce[0] ^ 0x8000000000000000L : nonce[0];
        nonce[1] = new Random().nextLong();
        return nonce;
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

    private long[] shiftLeft(int num, long[] block) {
        return new long[] {(block[0] << num) + (block[1] >>> (64-num)), (block[1] << num)};
    }

    private long[] shiftRight(int num, long[] block) {
        if (num >= 64) return new long[] {0, (block[0] >>> (num-64))};
        else return new long[] {(block[0] >>> num), (block[0] << (64-num)) + (block[1] >>> num)};
    }


    private long[][] buildTableForMultiplying(int n, long[] field_polynomial) {
        long[][] table = new long[n*2][2];
        long[] two_in_n = shiftLeft(1, field_polynomial);
        boolean msb = false;
        two_in_n[1] += 1;
        table[0][1] = 1;
        for (int i = 1; i < n*2; i++) {
            msb = (table[i-1][0] & 0x8000000000000000L) != 0;
            table[i] = shiftLeft(1, table[i-1]);
            if (msb) {
                table[i][0] ^= two_in_n[0];
                table[i][1] ^= two_in_n[1];
            }
        }
        return table;
    }

    private long[] multiplyInGF(long[] x, long[] y) {
        long[] result = new long[2];
        long[] polynominal = {0x8000000000000000L, 0x43L};
        long[][] table = buildTableForMultiplying(128, polynominal);
        Vector<Integer> sb_x = new Vector<Integer>();
        Vector<Integer> sb_y = new Vector<Integer>();
        for (int i = 127; i >= 0; i--) {
            if ((shiftRight(i, x)[1] & 1) != 0)
                sb_x.add(i);
            if ((shiftRight(i, y)[1] & 1) != 0)
                sb_y.add(i);
        }
        for (int i = 0; i < sb_x.size(); i++) {
            for (int j = 0; j < sb_y.size(); j++) {
                result[0] ^= table[sb_x.get(i)+sb_y.get(j)][0];
                result[1] ^= table[sb_x.get(i)+sb_y.get(j)][1];
            }
        }
        return result;
    }

    private void cutBytes(int number, long[] block) {
        long[] mask = {0xFFFFFFFFFFFFFFFFL, 0xFFFFFFFFFFFFFFFFL};
        for (int i = 0; i < number; i++) {
            mask = shiftLeft(8, mask);
        }
        block[0] &= mask[0];
        block[1] &= mask[1];
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

    private int countATForAAD(String aad_path, long[] authenticated_tag, long[] z, long[] subkeys){
        try {
            Camellia camellia = new Camellia();
            BufferedInputStream reader = new BufferedInputStream(new FileInputStream(aad_path), 16);
            long[] a_message = new long[2], h, temp;
            byte[] bytes = new byte[16];
            int i, length = 0;
            while ((i = (reader.read(bytes))) == 16) {
                length += i;
                a_message[0] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,0,8)).getLong();
                a_message[1] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,8,16)).getLong();
                h = camellia.cryptBlock(z[0]++, z[1], subkeys);
                temp = multiplyInGF(a_message, h);
                authenticated_tag[0] ^= temp[0];
                authenticated_tag[1] ^= temp[1];
            }
            if (i > 0 && i < 8){
                a_message[0] = 0;
                a_message[1] = 0;
                for (int j = 0; j < i; j++){
                    a_message[0] <<= 8;
                    a_message[0] += bytes[j];
                }
                a_message[0] <<= 64-(i*8);
            } else if (i >= 8){
                a_message[0] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,0,8)).getLong();
                a_message[1] = 0;
                for (int j = 8; j < i; j++){
                    a_message[1] <<= 8;
                    a_message[1] += bytes[j];
                }
                a_message[1] <<= 64-((i-8)*8);
            }
            if (i != -1) {
                length += i;
                h = camellia.cryptBlock(z[0]++, z[1], subkeys);
                temp = multiplyInGF(a_message, h);
                authenticated_tag[0] ^= temp[0];
                authenticated_tag[1] ^= temp[1];
            }
            reader.close();
            return length;
        } catch (Exception e) {
            System.out.println("Error occurred");
            System.out.println(e);
            return 0;
        }
    }

    public void Encrypt(String file_path, String aad_path,  String key) {
        try {
            Camellia camellia = new Camellia();
            int i;
            long[] lengths = new long[2];
            long[] temp;
            long[] nonce = createNonce();
            long[] subkeys = camellia.keySchedule(key);
            long[] authenticated_tag = new long[2];
            byte[] bytes = new byte[16];
            long[] z = camellia.cryptBlock(nonce[0] ^ 0x8000000000000000L, nonce[1], subkeys);
            long[] h;
            BufferedInputStream reader = new BufferedInputStream(new FileInputStream(file_path), 16);
            BufferedOutputStream writer = new BufferedOutputStream(new FileOutputStream(file_path+".crptd"));
            if (!aad_path.equals(""))
                lengths[0] = countATForAAD(aad_path, authenticated_tag, z, subkeys);
            long [] plaintext = new long[2];
            long[] y = camellia.cryptBlock(nonce[0], nonce[1], subkeys);
            long[] ciphertext;
            byte[][] ciphertext_bytes;
            ciphertext_bytes = longToByte(nonce[0], nonce[1]);
            writer.write(ciphertext_bytes[0]);
            writer.write(ciphertext_bytes[1]);
            while ((i = (reader.read(bytes))) == 16) {
                lengths[1] += i;
                plaintext[0] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,0,8)).getLong();
                plaintext[1] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,8,16)).getLong();
                ciphertext = camellia.cryptBlock(y[0], y[1]++, subkeys);
                ciphertext[0] ^= plaintext[0];
                ciphertext[1] ^= plaintext[1];
                ciphertext_bytes = longToByte(ciphertext[0], ciphertext[1]);
                writer.write(ciphertext_bytes[0]);
                writer.write(ciphertext_bytes[1]);
                writer.flush();
                h = camellia.cryptBlock(z[0]++, z[1], subkeys);
                temp = multiplyInGF(ciphertext, h);
                authenticated_tag[0] ^= temp[0];
                authenticated_tag[1] ^= temp[1];
            }
            if (i > 0 && i < 7){
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
                lengths[1] += i;
                ciphertext = camellia.cryptBlock(y[0], y[1]++, subkeys);
                cutBytes(16-i, ciphertext);
                ciphertext[0] ^= plaintext[0];
                ciphertext[1] ^= plaintext[1];
                ciphertext_bytes = longToByte(ciphertext[0], ciphertext[1]);
                writer.write(ciphertext_bytes[0]);
                writer.write(ciphertext_bytes[1]);
                writer.flush();
                h = camellia.cryptBlock(z[0]++, z[1], subkeys);
                temp = multiplyInGF(ciphertext, h);
                authenticated_tag[0] ^= temp[0];
                authenticated_tag[1] ^= temp[1];
            }
            h = camellia.cryptBlock(z[0]++, z[1], subkeys);
            temp = multiplyInGF(lengths, h);
            authenticated_tag[0] ^= temp[0];
            authenticated_tag[1] ^= temp[1];
            authenticated_tag = camellia.cryptBlock(authenticated_tag[0], authenticated_tag[1], subkeys);
            ciphertext_bytes = longToByte(authenticated_tag[0], authenticated_tag[1]);
            writer.write(ciphertext_bytes[0]);
            writer.write(ciphertext_bytes[1]);
            writer.flush();
            reader.close();
            writer.close();
        } catch (Exception e) {
            System.out.println("Error occurred");
            System.out.println(e);
            return;
        }
    }

    public boolean Decrypt(String file_path, String aad_path,  String key) {
        try {
            Camellia camellia = new Camellia();
            boolean at_correctness = false;
            int i;
            long[] lengths = new long[2];
            long[] temp;
            long[] subkeys = camellia.keySchedule(key);
            long[] authenticated_tag = new long[2];
            byte[] bytes = new byte[16];
            long[] h;
            BufferedInputStream reader = new BufferedInputStream(new FileInputStream(file_path), 16);
            BufferedOutputStream writer = new BufferedOutputStream(
                    new FileOutputStream(file_path.substring(0, file_path.lastIndexOf("."))));
            reader.read(bytes);
            long[] nonce = {
                    ByteBuffer.wrap(Arrays.copyOfRange(bytes, 0, 8)).getLong(),
                    ByteBuffer.wrap(Arrays.copyOfRange(bytes, 8, 16)).getLong()
            };
            long[] z = camellia.cryptBlock(nonce[0] ^ 0x8000000000000000L, nonce[1], subkeys);
            File file = new File(file_path);
            long counter = (file.length() / 16) - 2;
            if (!aad_path.equals(""))
                lengths[0] = countATForAAD(aad_path, authenticated_tag, z, subkeys);
            long [] ciphertext = new long[2];
            byte[][] ciphertext_bytes;
            long[] y = camellia.cryptBlock(nonce[0], nonce[1], subkeys);
            long[] plaintext;
            for (; counter > 1; counter--) {
                i = reader.read(bytes);
                lengths[1] += i;
                ciphertext[0] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,0,8)).getLong();
                ciphertext[1] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,8,16)).getLong();
                h = camellia.cryptBlock(z[0]++, z[1], subkeys);
                temp = multiplyInGF(ciphertext, h);
                authenticated_tag[0] ^= temp[0];
                authenticated_tag[1] ^= temp[1];

                plaintext = camellia.cryptBlock(y[0], y[1]++, subkeys);

                plaintext[0] ^= ciphertext[0];
                plaintext[1] ^= ciphertext[1];
                ciphertext_bytes = longToByte(plaintext[0], plaintext[1]);
                writer.write(ciphertext_bytes[0]);
                writer.write(ciphertext_bytes[1]);
                writer.flush();
            }
            i = reader.read(bytes);
            ciphertext[0] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,0,8)).getLong();
            ciphertext[1] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,8,16)).getLong();
            int extra_bytes = countExtraBytes(ciphertext);
            lengths[1] += i - extra_bytes;
            h = camellia.cryptBlock(z[0]++, z[1], subkeys);
            temp = multiplyInGF(ciphertext, h);
            authenticated_tag[0] ^= temp[0];
            authenticated_tag[1] ^= temp[1];
            plaintext = camellia.cryptBlock(y[0], y[1]++, subkeys);
            cutBytes(extra_bytes, plaintext);
            plaintext[0] ^= ciphertext[0];
            plaintext[1] ^= ciphertext[1];
            ciphertext_bytes = longToByte(plaintext[0], plaintext[1]);
            if (extra_bytes <= 8) {
                writer.write(ciphertext_bytes[0]);
                writer.write(ciphertext_bytes[1], 0, 8-extra_bytes);
            } else {
                writer.write(ciphertext_bytes[0], 0, 16-extra_bytes);
            }
            writer.flush();
            h = camellia.cryptBlock(z[0]++, z[1], subkeys);
            temp = multiplyInGF(lengths, h);
            authenticated_tag[0] ^= temp[0];
            authenticated_tag[1] ^= temp[1];
            authenticated_tag = camellia.cryptBlock(authenticated_tag[0], authenticated_tag[1], subkeys);
            reader.read(bytes);
            ciphertext[0] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,0,8)).getLong();
            ciphertext[1] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,8,16)).getLong();
            if (ciphertext[0] == authenticated_tag[0] && ciphertext[1] == authenticated_tag[1])
                at_correctness = true;
            reader.close();
            writer.close();
            return at_correctness;
        } catch (Exception e) {
            System.out.println("Error occurred");
            System.out.println(e);
            return false;
        }
    }
}
