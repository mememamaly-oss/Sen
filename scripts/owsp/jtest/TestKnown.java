import java.util.Random;
public class TestKnown {
    public static void main(String[] a) {
        Random r = new Random(123456789L);
        long v1 = r.nextLong();
        long v2 = r.nextLong();
        System.out.println(v1);
        System.out.println(v2);
        Random r2 = new Random();  // also verify seed formula assumptions
        System.out.println(r2.nextLong());
    }
}
