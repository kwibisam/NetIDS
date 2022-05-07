package side.utils;

import java.util.Iterator;

public class PeakableIterator<T> implements Iterator<T> {
    private Iterator<T> inner;
    private T element = null;

    public PeakableIterator(Iterator<T> inner) {
        this.inner = inner;
    }

    @Override
    public boolean hasNext() {
        if (element != null) {
            return true;
        }
        return inner.hasNext();
    }

    @Override
    public T next() {
        if (element != null) {
            T tmp = element;
            element = null;
            return tmp;
        }
        return inner.next();
    }

    public T peak() {
        if (element != null) {
            throw new RuntimeException("Can not peak multiple times in a row");
        }
        if (!hasNext()) {
            throw new RuntimeException("Itarator is empty");
        }
        element = inner.next();
        return element;
    }

    public void swallow() {
        if (element == null) {
            throw new RuntimeException("Can not swallow if not peaked");
        }
        element = null;
    }

    @Override
    public void remove() {
        if (element != null) {
            throw new RuntimeException("Can not remove peaked item");
        }
        inner.remove();
    }
}
