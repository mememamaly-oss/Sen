import java.util.Random;
public class TestJRand {
    public static void main(String[] a) throws Exception {
        for (int i = 0; i < 5; i++) {
            long t0 = System.nanoTime();
            long v = new Random().nextLong();
            long t1 = System.nanoTime();
            System.out.println(t0 + "," + v + "," + t1);
            Thread.sleep(3);
        }
    }
}
