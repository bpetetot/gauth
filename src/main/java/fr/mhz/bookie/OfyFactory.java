package fr.mhz.bookie;

import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Singleton;
import com.googlecode.objectify.ObjectifyFactory;
import fr.mhz.bookie.model.User;

import java.util.logging.Logger;

@Singleton
public class OfyFactory extends ObjectifyFactory {

    private Injector injector;

    /**
     * Logger for the OfyFactory class.
     */
    Logger logger = Logger.getLogger("OfyFactory");

    /**
     * Register our entity types
     */
    @Inject
    public OfyFactory(Injector injector) {
        this.injector = injector;

        long time = System.currentTimeMillis();

        this.register(User.class);

        long millis = System.currentTimeMillis() - time;
        logger.info("Ofy registration took " + millis + " ms");
    }

    /**
     * Use guice to make instances instead!
     */
    @Override
    public <T> T construct(Class<T> type) {
        return injector.getInstance(type);
    }

}
