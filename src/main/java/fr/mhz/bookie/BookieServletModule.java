package fr.mhz.bookie;

import com.google.inject.servlet.ServletModule;
import com.googlecode.objectify.ObjectifyFilter;
import fr.mhz.bookie.api.UserServlet;
import fr.mhz.bookie.auth.AuthenticatedFilter;
import fr.mhz.bookie.auth.DisconnectServlet;
import fr.mhz.bookie.auth.SignOutServlet;

public class BookieServletModule extends ServletModule {

    @Override protected void configureServlets() {

        filter("/*").through(ObjectifyFilter.class);

        filter("/api/*").through(AuthenticatedFilter.class);

        serve("/start/*").with(StaticServlet.class);

        serve("/api/users/me").with(UserServlet.class);

        serve("/api/signout").with(SignOutServlet.class);

        serve("/api/disconnect").with(DisconnectServlet.class);


    }

}
