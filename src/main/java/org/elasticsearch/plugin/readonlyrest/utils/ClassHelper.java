package org.elasticsearch.plugin.readonlyrest.utils;

public class ClassHelper {

	public static Class<?> loadClass(String classz) {
		try {
			return Class.forName(classz);
		} catch (ClassNotFoundException e) {
			return null;
		}
	}

	public static boolean isLoadable(String classz) {
		try {
			return (Class.forName(classz) != null);
		} catch (ClassNotFoundException e) {
			return false;
		}
	}
}
