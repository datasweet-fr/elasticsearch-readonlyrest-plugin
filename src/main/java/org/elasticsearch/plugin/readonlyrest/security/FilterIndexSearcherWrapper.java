/*
 *    This file is part of ReadonlyREST.
 *
 *    ReadonlyREST is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    ReadonlyREST is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with ReadonlyREST.  If not, see http://www.gnu.org/licenses/
 */

package org.elasticsearch.plugin.readonlyrest.security;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
import org.elasticsearch.common.settings.SettingsException;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.IndexSettings;
import org.elasticsearch.index.cache.bitset.BitsetFilterCache;
import org.elasticsearch.index.engine.EngineException;
import org.elasticsearch.index.query.ParsedQuery;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.index.query.QueryShardContext;
import org.elasticsearch.index.shard.IndexSearcherWrapper;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.index.shard.ShardUtils;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.RuleNotConfiguredException;
import org.elasticsearch.plugin.readonlyrest.utils.ThreadConstants;

public class FilterIndexSearcherWrapper extends IndexSearcherWrapper {
	private final BitsetFilterCache bitsetFilterCache;
	private final ThreadContext threadContext;
	private final Logger logger;
	private final Map<String, GroupSettings> rules;
	private static final String RULES_PREFIX = "rules";
	private final Function<ShardId, QueryShardContext> queryShardContextProvider;

	public FilterIndexSearcherWrapper(IndexSettings indexSettings,
			Function<ShardId, QueryShardContext> queryShardContextProvider, BitsetFilterCache bitsetFilterCache,
			ThreadContext threadContext) throws Exception {

		this.logger = Loggers.getLogger(this.getClass(), indexSettings.getSettings(), new String[0]);
		this.queryShardContextProvider = queryShardContextProvider;
		this.bitsetFilterCache = bitsetFilterCache;
		this.threadContext = threadContext;

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

		logger.info("Analyze for User Transient " + userTransient);

		GroupSettings rule = this.rules.get(userTransient.getRuleId());
		if (rule == null) {
			throw new IllegalStateException("Couldn't retrieve the rule from userTransient.");
		}

		ShardId shardId = ShardUtils.extractShardId(reader);
		if (shardId == null) {
			throw new IllegalStateException(
					LoggerMessageFormat.format("Couldn't extract shardId from reader [{}]", new Object[] { reader }));
		}

		final String indice = shardId.getIndexName();

		if (!rule.matchIndex(indice))
			return reader;

		String filter = rule.getFilter(new RuleRole(userTransient.getRuleId(), userTransient.getRole()));

		if (filter == null || filter.equals(""))
			return reader;

		try {
			BooleanQuery.Builder boolQuery = new BooleanQuery.Builder();
			QueryShardContext queryShardContext = this.queryShardContextProvider.apply(shardId);
			try {
				QueryBuilder qb = QueryBuilders.boolQuery().must(QueryBuilders.queryStringQuery(filter));
				ParsedQuery parsedQuery = queryShardContext.toQuery(qb);
				boolQuery.add(parsedQuery.query(), BooleanClause.Occur.SHOULD);
			} catch (Throwable queryBuilder) {
				logger.error("Error when wrapping the request: " + queryBuilder.getLocalizedMessage());
				throw queryBuilder;
			}
			boolQuery.setMinimumNumberShouldMatch(1);
			reader = DocumentReader.wrap(reader, this.bitsetFilterCache, new ConstantScoreQuery(boolQuery.build()));
			// logger.debug("Adding filter [" + filter + "] for indices [" + indice + "] for group [" + userTransient.getRuleId() + "]");
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

	protected IndexSearcher wrap(IndexSearcher indexSearcher) throws EngineException {
		DirectoryReader directoryReader = (DirectoryReader) indexSearcher.getIndexReader();
		if (directoryReader instanceof DocumentReader.DocumentDirectoryReader) {
			IndexSearcherWrapper indexSearcherWrapper = new IndexSearcherWrapper(
					(DocumentReader.DocumentDirectoryReader) directoryReader);
			indexSearcherWrapper.setQueryCache(indexSearcherWrapper.getQueryCache());
			indexSearcherWrapper.setQueryCachingPolicy(indexSearcherWrapper.getQueryCachingPolicy());
			indexSearcherWrapper.setSimilarity(indexSearcherWrapper.getSimilarity(true));
			return indexSearcherWrapper;
		}
		return indexSearcher;
	}

	static void intersectScorerAndRoleBits(Scorer scorer, SparseFixedBitSet sparseFixedBitSet,
			LeafCollector leafCollector, Bits acceptDocs) throws IOException {
		DocIdSetIterator it = ConjunctionDISI.intersectIterators(Arrays.asList(new DocIdSetIterator[] {
				new BitSetIterator((BitSet) sparseFixedBitSet, (long) sparseFixedBitSet.approximateCardinality()),
				scorer.iterator() }));
		int docId = it.nextDoc();
		while (docId < Integer.MAX_VALUE) {
			if (acceptDocs == null || acceptDocs.get(docId)) {
				leafCollector.collect(docId);
			}
			docId = it.nextDoc();
		}
	}

	static class IndexSearcherWrapper extends IndexSearcher {
		public IndexSearcherWrapper(DocumentReader.DocumentDirectoryReader directoryReader) {
			super((IndexReader) directoryReader);
		}

		protected void search(List<LeafReaderContext> leavesContext, Weight weight, Collector collector)
				throws IOException {
			for (LeafReaderContext ctx : leavesContext) {
				LeafCollector leafCollector;
				try {
					leafCollector = collector.getLeafCollector(ctx);
				} catch (CollectionTerminatedException e) {
					continue;
				}
				DocumentReader documentReader = (DocumentReader) ctx.reader();
				BitSet roleQueryBits = documentReader.getRoleQueryBits();
				if (roleQueryBits == null)
					continue;
				if (roleQueryBits instanceof SparseFixedBitSet) {
					Scorer scorer = weight.scorer(ctx);
					if (scorer == null)
						continue;
					SparseFixedBitSet sparseFixedBitSet = (SparseFixedBitSet) roleQueryBits;
					Bits wrappedLiveDocs = documentReader.getWrappedLiveDocs();
					try {
						FilterIndexSearcherWrapper.intersectScorerAndRoleBits(scorer, sparseFixedBitSet, leafCollector,
								wrappedLiveDocs);
					} catch (CollectionTerminatedException var12_14) {
					}
					continue;
				}
				BulkScorer bulkScorer = weight.bulkScorer(ctx);
				if (bulkScorer == null)
					continue;
				Bits liveDocs = documentReader.getLiveDocs();
				try {
					bulkScorer.score(leafCollector, liveDocs);
				} catch (CollectionTerminatedException realLiveDocs) {
				}
			}
		}
	}

}
