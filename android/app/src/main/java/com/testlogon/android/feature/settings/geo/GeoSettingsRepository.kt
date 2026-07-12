package com.testlogon.android.feature.settings.geo

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.geo.GeoApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Data layer for the geo-blocking settings screen over [GeoApi]. Mirrors the web GeoRulesPage: load the country
 * list + the viewer's detected country, and run an on-demand dry-run geo check. All calls fold into [ApiResult]
 * via the established [call] pattern (mirrors DefaultApiKeysRepository). No caching/migration (read surface).
 */
interface GeoSettingsRepository {

    suspend fun listCountries(): ApiResult<List<GeoCountry>>

    suspend fun getMyCountry(): ApiResult<MyCountry>

    /** Dry-run a geo configuration against the caller's IP. [mode] = null|"allow"|"block". */
    suspend fun check(mode: String?, countriesCsv: String?): ApiResult<GeoCheckOutcome>
}

@Singleton
class DefaultGeoSettingsRepository @Inject constructor(
    private val api: GeoApi,
    private val errorParser: ApiErrorParser,
) : GeoSettingsRepository {

    override suspend fun listCountries(): ApiResult<List<GeoCountry>> =
        withContext(Dispatchers.IO) {
            call { api.listCountries().countries.map { GeoCountry(code = it.code, name = it.name) } }
        }

    override suspend fun getMyCountry(): ApiResult<MyCountry> =
        withContext(Dispatchers.IO) {
            call {
                val dto = api.getMyCountry()
                MyCountry(
                    country = dto.country?.takeIf { it.isNotBlank() },
                    ip = dto.ip.orEmpty(),
                    source = dto.source.orEmpty(),
                )
            }
        }

    override suspend fun check(mode: String?, countriesCsv: String?): ApiResult<GeoCheckOutcome> =
        withContext(Dispatchers.IO) {
            call {
                val dto = api.check(
                    geoMode = mode?.takeIf { it.isNotBlank() },
                    geoCountries = countriesCsv?.takeIf { it.isNotBlank() },
                )
                GeoCheckOutcome(
                    allowed = dto.allowed,
                    country = dto.country,
                    matchedRule = dto.matchedRule,
                )
            }
        }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
