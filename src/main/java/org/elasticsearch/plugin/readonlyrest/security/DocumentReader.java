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

import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.FilterDirectoryReader;
import org.apache.lucene.index.FilterLeafReader;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.search.DocIdSetIterator;
import org.apache.lucene.search.FilteredDocIdSetIterator;
import org.apache.lucene.search.Query;
import org.apache.lucene.util.BitSet;
import org.apache.lucene.util.BitSetIterator;
import org.apache.lucene.util.Bits;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.logging.LoggerMessageFormat;
import org.elasticsearch.index.cache.bitset.BitsetFilterCache;

public final class DocumentReader extends FilterLeafReader {
	private final BitSet roleQueryBits;
	private volatile int numberOfDocs = -1;

	public static DocumentDirectoryReader wrap(DirectoryReader in, BitsetFilterCache bitsetFilterCache, Query query)
			throws IOException {
		return new DocumentDirectoryReader(in, bitsetFilterCache, query);
	}

	private DocumentReader(LeafReader in, BitsetFilterCache bitsetFilterCache, Query query) throws Exception {
		super(in);
		this.roleQueryBits = bitsetFilterCache.getBitSetProducer(query).getBitSet(in.getContext());
	}

	public Bits getLiveDocs() {
		final Bits currentLiveDocs = this.in.getLiveDocs();
		if (this.roleQueryBits == null) {
			return new Bits.MatchNoBits(this.in.maxDoc());
		}
		if (currentLiveDocs == null) {
			return this.roleQueryBits;
		}
		return new Bits() {

			public boolean get(int index) {
				return DocumentReader.this.roleQueryBits.get(index) && currentLiveDocs.get(index);
			}

			public int length() {
				return DocumentReader.this.roleQueryBits.length();
			}
		};
	}

	public int numDocs() {
		if (this.numberOfDocs == -1) {
			final Bits liveDocs = this.in.getLiveDocs();
			if (this.roleQueryBits == null) {
				this.numberOfDocs = 0;
			} else if (liveDocs == null) {
				this.numberOfDocs = this.roleQueryBits.cardinality();
			} else {
				try {
					FilteredDocIdSetIterator iterator = new FilteredDocIdSetIterator(
							(DocIdSetIterator) new BitSetIterator(this.roleQueryBits,
									(long) this.roleQueryBits.approximateCardinality())) {
						protected boolean match(int doc) {
							return liveDocs.get(doc);
						}
					};
					int counter = 0;
					int docId = iterator.nextDoc();
					while (docId < Integer.MAX_VALUE) {
						++counter;
						docId = iterator.nextDoc();
					}
					this.numberOfDocs = counter;
				} catch (IOException e) {
					throw ExceptionsHelper.convertToElastic((Exception) e);
				}
			}
		}
		return this.numberOfDocs;
	}

	public boolean hasDeletions() {
		return true;
	}

	public Object getCoreCacheKey() {
		return this.in.getCoreCacheKey();
	}

	BitSet getRoleQueryBits() {
		return this.roleQueryBits;
	}

	Bits getWrappedLiveDocs() {
		return this.in.getLiveDocs();
	}

	static final class DocumentDirectoryReader extends FilterDirectoryReader {
		private final Query query;
		private final BitsetFilterCache bitsetFilterCache;

		DocumentDirectoryReader(DirectoryReader in, BitsetFilterCache bitsetFilterCache, final Query query)
				throws IOException {
			super(in, new FilterDirectoryReader.SubReaderWrapper() {

				public LeafReader wrap(LeafReader reader) {
					try {
						return new DocumentReader(reader, bitsetFilterCache, query);
					} catch (Exception e) {
						throw ExceptionsHelper.convertToElastic(e);
					}
				}
			});
			this.bitsetFilterCache = bitsetFilterCache;
			this.query = query;
			DocumentDirectoryReader.verifyNoOtherDocumentDirectoryReaderIsWrapped(in);
		}

		protected DirectoryReader doWrapDirectoryReader(DirectoryReader in) throws IOException {
			return new DocumentDirectoryReader(in, this.bitsetFilterCache, this.query);
		}

		private static void verifyNoOtherDocumentDirectoryReaderIsWrapped(DirectoryReader reader) {
			if (reader instanceof FilterDirectoryReader) {
				FilterDirectoryReader filterDirectoryReader = (FilterDirectoryReader) reader;
				if (filterDirectoryReader instanceof DocumentDirectoryReader) {
					throw new IllegalArgumentException(LoggerMessageFormat.format("Can't wrap [{}] another reader",
							new Object[] { DocumentDirectoryReader.class }));
				}
				DocumentDirectoryReader
						.verifyNoOtherDocumentDirectoryReaderIsWrapped(filterDirectoryReader.getDelegate());
			}
		}

		public Object getCoreCacheKey() {
			return this.in.getCoreCacheKey();
		}
	}
}
