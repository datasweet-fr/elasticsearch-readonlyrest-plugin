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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.apache.lucene.index.BinaryDocValues;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.FieldInfo;
import org.apache.lucene.index.FieldInfos;
import org.apache.lucene.index.Fields;
import org.apache.lucene.index.FilterDirectoryReader;
import org.apache.lucene.index.FilterLeafReader;
import org.apache.lucene.index.LeafReader;
import org.apache.lucene.index.NumericDocValues;
import org.apache.lucene.index.PointValues;
import org.apache.lucene.index.SortedDocValues;
import org.apache.lucene.index.SortedNumericDocValues;
import org.apache.lucene.index.SortedSetDocValues;
import org.apache.lucene.index.StoredFieldVisitor;
import org.apache.lucene.index.Terms;
import org.apache.lucene.index.TermsEnum;
import org.apache.lucene.util.Bits;
import org.apache.lucene.util.BytesRef;
import org.apache.lucene.util.FilterIterator;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.logging.LoggerMessageFormat;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.common.xcontent.support.XContentMapValues;

public final class FieldSubsetReader
extends FilterLeafReader {
    private final FieldInfos fieldInfos;
    private final String[] fieldNames;

    public static DirectoryReader wrap(DirectoryReader in, Set<String> fieldNames) throws IOException {
        return new FieldSubsetDirectoryReader(in, fieldNames);
    }

    FieldSubsetReader(LeafReader in, Set<String> fieldNames) {
        super(in);
        ArrayList<FieldInfo> filteredInfos = new ArrayList<FieldInfo>();
        for (FieldInfo fi : in.getFieldInfos()) {
            if (!fieldNames.contains(fi.name)) continue;
            filteredInfos.add(fi);
        }
        FieldInfo[] fi = new FieldInfo[filteredInfos.size()];
        fi = filteredInfos.toArray(fi);
        this.fieldInfos = new FieldInfos(fi);
        this.fieldNames = fieldNames.toArray(new String[fieldNames.size()]);
    }

    boolean hasField(String field) {
        return this.fieldInfos.fieldInfo(field) != null;
    }

    public FieldInfos getFieldInfos() {
        return this.fieldInfos;
    }

    public Fields getTermVectors(int docID) throws IOException {
        Object f = super.getTermVectors(docID);
        if (f == null) {
            return null;
        }
        f = new FieldFilterFields((Fields) f);
        Fields fields = null;
        if (f instanceof Fields)
        	fields = (Fields) f;
        if (fields != null && fields.iterator().hasNext())
        	return fields;
        else
        	return null;
    }

    public void document(int docID, final StoredFieldVisitor visitor) throws IOException {
        super.document(docID, new StoredFieldVisitor(){

            public void binaryField(FieldInfo fieldInfo, byte[] value) throws IOException {
                if ("_source".equals(fieldInfo.name)) {
                    BytesArray bytes = new BytesArray(value);
                    Tuple<XContentType, Map<String, Object>> result = XContentHelper.convertToMap((BytesReference)bytes, true);
                    Map<String, Object> transformedSource = XContentMapValues.filter((result.v2()), FieldSubsetReader.this.fieldNames, null);
                    XContentBuilder xContentBuilder = XContentBuilder.builder((result.v1()).xContent()).map(transformedSource);
                    visitor.binaryField(fieldInfo, BytesReference.toBytes(xContentBuilder.bytes()));
                } else {
                    visitor.binaryField(fieldInfo, value);
                }
            }

            public void stringField(FieldInfo fieldInfo, byte[] value) throws IOException {
                visitor.stringField(fieldInfo, value);
            }

            public void intField(FieldInfo fieldInfo, int value) throws IOException {
                visitor.intField(fieldInfo, value);
            }

            public void longField(FieldInfo fieldInfo, long value) throws IOException {
                visitor.longField(fieldInfo, value);
            }

            public void floatField(FieldInfo fieldInfo, float value) throws IOException {
                visitor.floatField(fieldInfo, value);
            }

            public void doubleField(FieldInfo fieldInfo, double value) throws IOException {
                visitor.doubleField(fieldInfo, value);
            }

            public StoredFieldVisitor.Status needsField(FieldInfo fieldInfo) throws IOException {
                return FieldSubsetReader.this.hasField(fieldInfo.name) ? visitor.needsField(fieldInfo) : StoredFieldVisitor.Status.NO;
            }
        });
    }

    public Fields fields() throws IOException {
        return new FieldFilterFields(super.fields());
    }

    public NumericDocValues getNumericDocValues(String field) throws IOException {
        return this.hasField(field) ? super.getNumericDocValues(field) : null;
    }

    public BinaryDocValues getBinaryDocValues(String field) throws IOException {
        return this.hasField(field) ? super.getBinaryDocValues(field) : null;
    }

    public SortedDocValues getSortedDocValues(String field) throws IOException {
        return this.hasField(field) ? super.getSortedDocValues(field) : null;
    }

    public SortedNumericDocValues getSortedNumericDocValues(String field) throws IOException {
        return this.hasField(field) ? super.getSortedNumericDocValues(field) : null;
    }

    public SortedSetDocValues getSortedSetDocValues(String field) throws IOException {
        return this.hasField(field) ? super.getSortedSetDocValues(field) : null;
    }

    public NumericDocValues getNormValues(String field) throws IOException {
        return this.hasField(field) ? super.getNormValues(field) : null;
    }

    public Bits getDocsWithField(String field) throws IOException {
        return this.hasField(field) ? super.getDocsWithField(field) : null;
    }

    public Object getCoreCacheKey() {
        return this.in.getCoreCacheKey();
    }

    public PointValues getPointValues() {
        PointValues points = super.getPointValues();
        if (points == null) {
            return null;
        }
        return new FieldFilterPointValues(points);
    }

    final class FieldFilterPointValues
    extends PointValues {
        private final PointValues in;

        FieldFilterPointValues(PointValues in) {
            this.in = in;
        }

        public void intersect(String fieldName, PointValues.IntersectVisitor visitor) throws IOException {
            if (!FieldSubsetReader.this.hasField(fieldName)) {
                return;
            }
            this.in.intersect(fieldName, visitor);
        }

        public byte[] getMinPackedValue(String fieldName) throws IOException {
            if (FieldSubsetReader.this.hasField(fieldName)) {
                return this.in.getMinPackedValue(fieldName);
            }
            return null;
        }

        public byte[] getMaxPackedValue(String fieldName) throws IOException {
            if (FieldSubsetReader.this.hasField(fieldName)) {
                return this.in.getMaxPackedValue(fieldName);
            }
            return null;
        }

        public int getNumDimensions(String fieldName) throws IOException {
            if (FieldSubsetReader.this.hasField(fieldName)) {
                return this.in.getNumDimensions(fieldName);
            }
            return 0;
        }

        public int getBytesPerDimension(String fieldName) throws IOException {
            if (FieldSubsetReader.this.hasField(fieldName)) {
                return this.in.getBytesPerDimension(fieldName);
            }
            return 0;
        }

        public long size(String fieldName) {
            if (FieldSubsetReader.this.hasField(fieldName)) {
                return this.in.size(fieldName);
            }
            return 0;
        }

        public int getDocCount(String fieldName) {
            if (FieldSubsetReader.this.hasField(fieldName)) {
                return this.in.getDocCount(fieldName);
            }
            return 0;
        }

		@Override
		public long estimatePointCount(String fieldName, IntersectVisitor visitor) {
			// TODO Auto-generated method stub
			return 0;
		}
    }

    class FieldNamesTermsEnum
    extends FilterLeafReader.FilterTermsEnum {
        FieldNamesTermsEnum(TermsEnum in) {
            super(in);
        }

        boolean accept(BytesRef term) {
            return FieldSubsetReader.this.hasField(term.utf8ToString());
        }

        public boolean seekExact(BytesRef term) throws IOException {
            return this.accept(term) && this.in.seekExact(term);
        }

        public TermsEnum.SeekStatus seekCeil(BytesRef term) throws IOException {
            TermsEnum.SeekStatus status = this.in.seekCeil(term);
            if (status == TermsEnum.SeekStatus.END || this.accept(this.term())) {
                return status;
            }
            return this.next() == null ? TermsEnum.SeekStatus.END : TermsEnum.SeekStatus.NOT_FOUND;
        }

        public BytesRef next() throws IOException {
            BytesRef next;
            while ((next = this.in.next()) != null && !this.accept(next)) {
            }
            return next;
        }

        public void seekExact(long ord) throws IOException {
            throw new UnsupportedOperationException();
        }

        public long ord() throws IOException {
            throw new UnsupportedOperationException();
        }
    }

    class FieldNamesTerms
    extends FilterLeafReader.FilterTerms {
        FieldNamesTerms(Terms in) {
            super(in);
        }

        public TermsEnum iterator() throws IOException {
            return new FieldNamesTermsEnum(this.in.iterator());
        }

        public int getDocCount() throws IOException {
            return -1;
        }

        public long getSumDocFreq() throws IOException {
            return -1;
        }

        public long getSumTotalTermFreq() throws IOException {
            return -1;
        }

        public long size() throws IOException {
            return -1;
        }
    }

    class FieldFilterFields
    extends FilterLeafReader.FilterFields {
        public FieldFilterFields(Fields in) {
            super(in);
        }

        public int size() {
            return -1;
        }

        public Iterator<String> iterator() {
            return new FilterIterator<String, String>(super.iterator()){

                protected boolean predicateFunction(String field) {
                    return FieldSubsetReader.this.hasField(field);
                }
            };
        }

        public Terms terms(String field) throws IOException {
            if (!FieldSubsetReader.this.hasField(field)) {
                return null;
            }
            if ("_field_names".equals(field)) {
                Object terms = super.terms(field);
                if (terms != null) {
                    terms = new FieldNamesTerms((Terms)terms);
                }
                return (Terms) terms;
            }
            return super.terms(field);
        }

    }

    static class FieldSubsetDirectoryReader
    extends FilterDirectoryReader {
        private final Set<String> fieldNames;

        FieldSubsetDirectoryReader(DirectoryReader in, Set<String> fieldNames) throws IOException {
            super(in, new FilterDirectoryReader.SubReaderWrapper(){

                public LeafReader wrap(LeafReader reader) {
                    return new FieldSubsetReader(reader, fieldNames);
                }
            });
            this.fieldNames = fieldNames;
            FieldSubsetDirectoryReader.verifyNoOtherFieldSubsetDirectoryReaderIsWrapped(in);
        }

        protected DirectoryReader doWrapDirectoryReader(DirectoryReader in) throws IOException {
            return new FieldSubsetDirectoryReader(in, this.fieldNames);
        }

        public Set<String> getFieldNames() {
            return this.fieldNames;
        }

        private static void verifyNoOtherFieldSubsetDirectoryReaderIsWrapped(DirectoryReader reader) {
            if (reader instanceof FilterDirectoryReader) {
                FilterDirectoryReader filterDirectoryReader = (FilterDirectoryReader)reader;
                if (filterDirectoryReader instanceof FieldSubsetDirectoryReader) {
                    throw new IllegalArgumentException(LoggerMessageFormat.format("Can't wrap [{}] twice", new Object[]{FieldSubsetDirectoryReader.class}));
                }
                FieldSubsetDirectoryReader.verifyNoOtherFieldSubsetDirectoryReaderIsWrapped(filterDirectoryReader.getDelegate());
            }
        }

        public Object getCoreCacheKey() {
            return this.in.getCoreCacheKey();
        }

    }

}

