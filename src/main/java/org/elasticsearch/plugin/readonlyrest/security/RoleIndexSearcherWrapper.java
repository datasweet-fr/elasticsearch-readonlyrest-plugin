package org.elasticsearch.plugin.readonlyrest.security;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import org.apache.logging.log4j.Logger;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.LeafReaderContext;
import org.apache.lucene.search.BooleanClause;
import org.apache.lucene.search.BooleanQuery;
import org.apache.lucene.search.BulkScorer;
import org.apache.lucene.search.CollectionTerminatedException;
import org.apache.lucene.search.Collector;
import org.apache.lucene.search.ConjunctionDISI;
import org.apache.lucene.search.ConstantScoreQuery;
import org.apache.lucene.search.DocIdSetIterator;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.LeafCollector;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.Scorer;
import org.apache.lucene.search.Weight;
import org.apache.lucene.util.BitSet;
import org.apache.lucene.util.BitSetIterator;
import org.apache.lucene.util.Bits;
import org.apache.lucene.util.SparseFixedBitSet;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.logging.LoggerMessageFormat;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.index.IndexService;
import org.elasticsearch.index.IndexSettings;
import org.elasticsearch.index.engine.EngineException;
import org.elasticsearch.index.query.ParsedQuery;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.index.query.QueryShardContext;
import org.elasticsearch.index.shard.IndexSearcherWrapper;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.index.shard.ShardUtils;
import org.elasticsearch.plugin.readonlyrest.utils.ThreadConstants;

import com.unboundid.util.args.ArgumentException;

public class RoleIndexSearcherWrapper extends IndexSearcherWrapper {
    private final Logger logger;
    private final IndexSettings indexSettings;
    private final Function<ShardId, QueryShardContext> queryShardContextProvider;
    private final ThreadContext threadContext;
	private final Map<String, GroupSettings> rules;
    private static final String RULES_PREFIX = "rules";
	
	public RoleIndexSearcherWrapper(IndexService indexService) throws Exception {
        if (indexService == null) {
            throw new ArgumentException("Please provide an indexService");
        }
        this.indexSettings = indexService.getIndexSettings();
		this.logger = Loggers.getLogger(this.getClass(), this.indexSettings.getSettings(), new String[0]);
        this.queryShardContextProvider = shardId -> indexService.newQueryShardContext(shardId.id(), null, null);
        this.threadContext = indexService.getThreadPool().getThreadContext();

		Settings configFileSettings = indexSettings.getSettings().getByPrefix("readonlyrest.");
		boolean enabled = configFileSettings.getAsBoolean("enable", false);
		if (enabled) {
			String configFile = "";
			Settings b = null;
			try {
				configFile = configFileSettings.get("config");
				Path path = FileSystems.getDefault().getPath(configFile);
				b = Settings.builder().loadFromPath(path).build();
			} catch (Exception e) {
				String errorMsg = "Can't load config from file " + configFile;
				throw new ElasticsearchException(errorMsg);
			}
			Settings s = b.getByPrefix("readonlyrest.");
			boolean isDocFilteringEnabled = s.getAsBoolean("doc_filter_enable", false);
			if (isDocFilteringEnabled) {
				this.rules = readSettings(s);
			} else {
				this.rules = null;
			}
		} else {
			this.rules = null;
		}
	}

	@Override
	protected DirectoryReader wrap(DirectoryReader reader) {
		if (this.rules == null) {
			logger.warn("Document filtering not available. Return defaut reader");
			return reader;
		}

		UserTransient userTransient = threadContext.getTransient(ThreadConstants.userTransient);
		if (userTransient == null) {
			throw new IllegalStateException("Couldn't extract userTransient from threadContext.");
		}

		// No filtering for special users.
		if (userTransient.isAdmin() || userTransient.isKibana() || userTransient.isIndexer())
			return reader;

		GroupSettings rule = this.rules.get(userTransient.getRuleId());
		if (rule == null) {
			throw new IllegalStateException("Couldn't retrieve the rule from userTransient.");
        }

        ShardId shardId = ShardUtils.extractShardId(reader);
		if (shardId == null) {
			throw new IllegalStateException(
					LoggerMessageFormat.format("Couldn't extract shardId from reader [{}]", new Object[] { reader }));
		}

        String indice = shardId.getIndexName();

		if (!rule.matchIndex(indice)) {
			logger.warn("NO MATCHING INDEX : [{}]", indice);
			return reader;
		}

		String filter = rule.getFilter(new RuleRole(userTransient.getRuleId(), userTransient.getRole()));

		if (filter == null || filter.equals("")) {
			logger.warn("NO FILTER FOR RULE [{}]", userTransient.getRuleId());
			return reader;
        }
		
		// logger.info("WE WILL FILTER ON INDEX " + indice + " WITH FILTER " + filter);

		try {
			BooleanQuery.Builder boolQuery = new BooleanQuery.Builder();
            boolQuery.setMinimumNumberShouldMatch(1);
            QueryShardContext queryShardContext = this.queryShardContextProvider.apply(shardId);
            XContentParser parser = XContentFactory.xContent(filter).createParser(queryShardContext.getXContentRegistry(), filter);
            QueryBuilder queryBuilder = queryShardContext.newParseContext(parser).parseInnerQueryBuilder().get(); // Optional ???
            ParsedQuery parsedQuery = queryShardContext.toFilter(queryBuilder);
			boolQuery.add(parsedQuery.query(), BooleanClause.Occur.SHOULD);
            reader = DocumentFilterReader.wrap(reader, new ConstantScoreQuery(boolQuery.build()));
			return reader;
		} catch (IOException e) {
			this.logger.error("Unable to setup document security");
			throw ExceptionsHelper.convertToElastic((Exception) e);
		}
    }
    


	private Map<String, GroupSettings> readSettings(Settings s) {
		try {
			Map<String, Settings> r = s.getGroups(RULES_PREFIX);
			Map<String, GroupSettings> res = new HashMap<String, GroupSettings>();
			for (Settings ss : r.values()) {
				GroupSettings gs = GroupSettings.CreateFromSettings(ss);
				res.put(gs.getRuleId(), gs);
			}
			return res;
		} catch (Exception e) {
			logger.error("Unable to read settings for filter", e);
			return null;
		}
	}

	@Override
	protected IndexSearcher wrap(IndexSearcher indexSearcher) throws EngineException {
		// DirectoryReader directoryReader = (DirectoryReader) indexSearcher.getIndexReader();
		// if (directoryReader instanceof DocumentReader.DocumentDirectoryReader) {
		// 	IndexSearcherWrapper indexSearcherWrapper = new IndexSearcherWrapper((DocumentReader.DocumentDirectoryReader) directoryReader);

		// 	indexSearcherWrapper.setQueryCache(indexSearcherWrapper.getQueryCache());
		// 	indexSearcherWrapper.setQueryCache(null);
		// 	indexSearcherWrapper.setQueryCachingPolicy(indexSearcherWrapper.getQueryCachingPolicy());


		// 	indexSearcherWrapper.setSimilarity(indexSearcherWrapper.getSimilarity(true));
		// 	return indexSearcherWrapper;
		// }
		// return indexSearcher;
		// if (directoryReader instanceof DocumentFilterReader.DocumentFilterDirectoryReader) {
		// 	IndexSearcher idw = new IndexSearcher(directoryReader);
		// 	idw.setQueryCache(null);
		// 	return idw;

		// indexSearcher.setQueryCache(null);
		// this.logger.info("INDEX SEARCHER WRAP [{}]", indexSearcher.getQueryCache());

		// return indexSearcher;
		return indexSearcher;

    }
}
