package camp.xit.google.api.credentials;

import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

class ExpirationSupplier<T> implements Supplier<T> {

    private final ExpirySupplier<T> delegate;
    private final long durationNanos;
    // The special value 0 means "not yet initialized".
    private transient volatile long expirationNanos;
    private transient volatile long lastModification;
    private transient volatile T value;

    public ExpirationSupplier(ExpirySupplier<T> delegate, long duration, TimeUnit unit) {
        this.delegate = delegate;
        this.durationNanos = unit.toNanos(duration);
        this.lastModification = -1;
    }

    @Override
    public T get() {
        // Another variant of Double Checked Locking.
        //
        // We use two volatile reads. We could reduce this to one by
        // putting our fields into a holder class, but (at least on x86)
        // the extra memory consumption and indirection are more
        // expensive than the extra volatile reads.
        long nanos = expirationNanos;
        long now = System.nanoTime();
        long nowMillis = System.currentTimeMillis();
        if (nanos == 0 || now - nanos >= 0) {
            synchronized (this) {
                if (nanos == expirationNanos) { // recheck for lost race
                    T t = delegate.get(value, lastModification);
                    value = t;
                    nanos = now + durationNanos;
                    // In the very unlikely event that nanos is 0, set it to 1;
                    // no one will notice 1 ns of tardiness.
                    expirationNanos = (nanos == 0) ? 1 : nanos;
                    lastModification = nowMillis;
                    return t;
                }
            }
        }
        return value;
    }

    public static <T> java.util.function.Supplier<T> of(ExpirySupplier<T> provider, long duration, TimeUnit unit) {
        return new ExpirationSupplier<>(provider, duration, unit);
    }

    @FunctionalInterface
    public interface ExpirySupplier<T> {

        /**
         * Gets a result.
         *
         * @param value
         * @param lastModification
         * @return a result
         */
        T get(T value, long lastModification);
    }
}
