public class ClockAlign {
    public static void main(String[] a) throws Exception {
        for (int i = 0; i < 3; i++) {
            long nano = System.nanoTime();
            long milli = System.currentTimeMillis();
            System.out.println(nano + "," + milli);
            Thread.sleep(50);
        }
    }
}
