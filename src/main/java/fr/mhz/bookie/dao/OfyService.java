package fr.mhz.bookie.dao;

import com.google.inject.Inject;
import com.googlecode.objectify.Objectify;
import com.googlecode.objectify.ObjectifyService;

public class OfyService {

    @Inject
    public static void setObjectifyFactory(OfyFactory factory) {
        ObjectifyService.setFactory(factory);
    }

    /**
     * @return our extension to Objectify
     */
    public static Objectify ofy() {
        return ObjectifyService.ofy();
    }

}
