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

package org.elasticsearch.plugin.readonlyrest.acl.blocks;

import java.util.Arrays;
import java.util.List;

import org.elasticsearch.common.settings.Settings;

public class Group {
	private String group;
	private List<String> indices;
	private TYPE type;
	private List<String> filters;
	public static final String ADMIN = "Admin";
	public static final String EDITOR = "Editor";
	public static final String VIEWER = "Viewer";
	
	public Group(Settings s) {
		if (s != null) {
			this.type = TYPE.valueOf(s.get("type").toUpperCase());
			this.group = s.get("group");
			this.indices = Arrays.asList(s.getAsArray("indices"));
			this.filters = Arrays.asList(s.getAsArray("filters"));
		}
	}

	public String getGroup() {
		return group;
	}

	public void setGroup(String group) {
		this.group = group;
	}

	public List<String> getIndices() {
		return indices;
	}
	
	public enum TYPE {
		VIEWER,
		EDITOR,
		ADMIN;
		
		public String valuesString() {
            StringBuilder sb = new StringBuilder();
            for (TYPE v : values()) {
                sb.append(v.toString()).append(",");
            }
            sb.deleteCharAt(sb.length() - 1);
            return sb.toString();
        }
	};


	public void setIndices(List<String> indices) {
		this.indices = indices;
	}


	public TYPE getType() {
		return type;
	}


	public void setType(TYPE type) {
		this.type = type;
	}

	public List<String> getFilters() {
		return filters;
	}

	public void setFilters(List<String> filters) {
		this.filters = filters;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("{").append("TYP:").append(type).append(", ");
		sb.append("GRP:").append(group).append(", ");
		sb.append("IDX:");
		indices.forEach(item -> {
			sb.append(item);
			if (indices.indexOf(item) < indices.size() - 1)
				sb.append(",");
		});
		sb.append("FTR:");
		filters.forEach(item -> {
			sb.append(item);
			if (filters.indexOf(item) < filters.size() - 1)
				sb.append(",");
		});
		sb.append("}");
		return sb.toString();
	}
}