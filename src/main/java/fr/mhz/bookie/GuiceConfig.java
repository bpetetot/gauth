package fr.mhz.bookie;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Singleton;
import com.google.inject.servlet.GuiceServletContextListener;
import com.google.inject.servlet.ServletModule;
import com.googlecode.objectify.ObjectifyFilter;
import fr.mhz.bookie.api.HomeServlet;
import fr.mhz.bookie.api.UserServlet;
import fr.mhz.bookie.auth.AuthenticatedFilter;
import fr.mhz.bookie.auth.DisconnectServlet;
import fr.mhz.bookie.auth.SignOutServlet;

import javax.servlet.ServletContextEvent;
import java.util.logging.Logger;

public class GuiceConfig extends GuiceServletContextListener {

    /**
     * Logger for the GuiceConfig class.
     */
    Logger logger = Logger.getLogger("GuiceConfig");

    static class BookieServletModule extends ServletModule {

        @Override
        protected void configureServlets() {

            // Filters
            filter("/*").through(ObjectifyFilter.class);
            filter("/api/*").through(AuthenticatedFilter.class);

            // Servlets
            serve("/home", "/").with(HomeServlet.class);
            serve("/api/users/me").with(UserServlet.class);
            serve("/api/signout").with(SignOutServlet.class);
            serve("/api/disconnect").with(DisconnectServlet.class);

        }

    }

    /**
     * Public so it can be used by unit tests
     */
    public static class BookieModule extends AbstractModule {

        @Override
        protected void configure() {

            requestStaticInjection(OfyService.class);
            bind(ObjectifyFilter.class).in(Singleton.class);

        }

    }

    /**
     * Logs the time required to initialize Guice
     */
    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        long time = System.currentTimeMillis();

        super.contextInitialized(servletContextEvent);

        long millis = System.currentTimeMillis() - time;
        logger.info("Guice initialization took " + millis + " ms");
    }


    @Override
    protected Injector getInjector() {

        return Guice.createInjector(new BookieServletModule(), new BookieModule());

    }

}
