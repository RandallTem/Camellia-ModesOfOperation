import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class OMAC {

    private long[][] getSubKeys(long[] subkeys) {
        Camellia camellia = new Camellia();
        long[][] k = new long[3][2];
        k[0] = camellia.cryptBlock(0L, 0L, subkeys);
        k[1][0] = (k[0][0] << 1) + (k[0][1] >>> 63);
        k[1][1] = k[0][1] << 1;
        if ((k[0][0] & 0x8000000000000000L) != 0)
            k[1][1] ^= 0x0000000000000087L;
        k[2][0] = (k[1][0] << 1) + (k[1][1] >>> 63);
        k[2][1] = k[1][1] << 1;
        if ((k[1][0] & 0x8000000000000000L) != 0)
            k[2][1] ^= 0x0000000000000087L;
        return k;
    }

    public long[] getMAC(String path, String key) {
        try {
            Camellia camellia = new Camellia();
            BufferedInputStream reader = new BufferedInputStream(new FileInputStream(path), 16);
            File file = new File(path);
            byte[] bytes = new byte[16];
            long counter = (file.length() % 16 == 0) ? file.length() / 16 - 1 : file.length() / 16;
            long[] message = new long[2];
            long[] ciphertext = {0L, 0L};
            long[] subkeys = camellia.keySchedule(key);
            for (; counter > 0; counter--) {
                reader.read(bytes);
                message[0] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,0,8)).getLong() ^ ciphertext[0];
                message[1] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,8,16)).getLong() ^ ciphertext[1];
                ciphertext = camellia.cryptBlock(message[0], message[1], subkeys);
            }
            bytes = new byte[16];
            int i = reader.read(bytes);
            message[0] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,0,8)).getLong();
            message[1] = ByteBuffer.wrap(Arrays.copyOfRange(bytes,8,16)).getLong();
            long[][] keys = getSubKeys(subkeys);
            if (i == 16) {
                message[0] ^= keys[1][0];
                message[1] ^= keys[1][1];
            } else {
                message[i / 8] += (0x8000000000000000L >>> (i % 8)*8);
                message[0] ^= keys[2][0];
                message[1] ^= keys[2][1];
            }
            message[0] ^= ciphertext[0];
            message[1] ^= ciphertext[1];
            ciphertext = camellia.cryptBlock(message[0], message[1], subkeys);
            return ciphertext;
        } catch (Exception e) {
            System.out.println("Error occurred");
            System.out.println(e);
            return new long[2];
        }
    }
}
