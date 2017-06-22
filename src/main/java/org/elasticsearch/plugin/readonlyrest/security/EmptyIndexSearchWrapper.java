package org.elasticsearch.plugin.readonlyrest.security;

import java.util.ArrayList;

import org.apache.lucene.index.DirectoryReader;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.Index;
import org.elasticsearch.index.IndexService;
import org.elasticsearch.index.shard.IndexSearcherWrapper;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.Group;
import org.elasticsearch.plugin.readonlyrest.utils.ThreadConstants;

public class EmptyIndexSearchWrapper extends IndexSearcherWrapper {

	protected Index index;
	protected ThreadContext threadContext;
	
	public EmptyIndexSearchWrapper(IndexService indexservice, Settings settings) {
		this.index = indexservice.index();
		this.threadContext = indexservice.getThreadPool().getThreadContext();
	}
	
	protected DirectoryReader wrap(DirectoryReader reader) {
		ArrayList<String> userGroups = threadContext.getTransient(ThreadConstants.userGroup);
		if (userGroups != null && userGroups.contains(Group.ADMIN))
			return subWrap(reader);
		
		return reader;
	}

	protected DirectoryReader subWrap(final DirectoryReader reader) {
		return reader;
	}
}
