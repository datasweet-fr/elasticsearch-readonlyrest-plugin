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
package org.elasticsearch.plugin.readonlyrest.acl.blocks.rules;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugin.readonlyrest.acl.LoggedUser;
import org.elasticsearch.plugin.readonlyrest.utils.ConfigReaderHelper;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.elasticsearch.plugin.readonlyrest.utils.ConfigReaderHelper.optionalAttributeValue;

public class CachedAsyncAuthorizationDecorator extends AsyncAuthorization {

  private static String ATTRIBUTE_CACHE_TTL = "cache_ttl_in_sec";

  private final AsyncAuthorization underlying;
  private final Cache<String, Boolean> cache;

  public CachedAsyncAuthorizationDecorator(AsyncAuthorization underlying, Duration ttl) {
    this.underlying = underlying;
    this.cache = CacheBuilder.newBuilder()
                             .expireAfterWrite(ttl.toMillis(), TimeUnit.MILLISECONDS)
                             .build();
  }

  public static AsyncAuthorization wrapInCacheIfCacheIsEnabled(AsyncAuthorization authorization, Settings settings) {
    return optionalAttributeValue(ATTRIBUTE_CACHE_TTL, settings, ConfigReaderHelper.toDuration())
        .map(ttl -> ttl.isZero()
            ? authorization
            : new CachedAsyncAuthorizationDecorator(authorization, ttl))
        .orElse(authorization);
  }

  @Override
  public CompletableFuture<Boolean> authorize(LoggedUser user) {
    Boolean authorizationResult = cache.getIfPresent(user.getId());
    if (authorizationResult == null) {
      return underlying.authorize(user)
                       .thenApply(result -> {
                         cache.put(user.getId(), result);
                         return result;
                       });
    }
    return CompletableFuture.completedFuture(authorizationResult);
  }

  @Override
  public String getKey() {
    return underlying.getKey();
  }

}
