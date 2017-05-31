package org.elasticsearch.plugin.readonlyrest.utils;

import java.util.ArrayList;

import org.elasticsearch.plugin.readonlyrest.wiring.requestcontext.RequestContext;

public class RequestUtils {

	private static String NodesInfoRequest = "NodesInfoRequest";
	private static String MainRequest = "MainRequest";
	private static String SearchRequest = "SearchRequest";
	private static String ClusterHealthRequest = "ClusterHealthRequest";
	private static String MultiGetShardRequest = "MultiGetShardRequest";
	private static String MultiGetRequest = "MultiGetRequest";
	
	private static ArrayList<String> getKibanaPingRequest() {
		ArrayList<String> pingRequest = new ArrayList<String>() {};
		pingRequest.add(NodesInfoRequest);
		pingRequest.add(MainRequest);
		pingRequest.add(SearchRequest);
		pingRequest.add(ClusterHealthRequest);
		pingRequest.add(MultiGetShardRequest);
		pingRequest.add(MultiGetRequest);
		
		return pingRequest;
	}
	
	public static boolean isKibanaPingRequest(RequestContext rc) {
		return (!rc.getLoggedInUser().isPresent() || rc.getLoggedInUser().get().getId().equals("Kibana")) &&
				getKibanaPingRequest().contains(rc.getUnderlyingRequest().getClass().getSimpleName());
	}
}
