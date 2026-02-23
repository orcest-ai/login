import json
import os
from typing import Any

from google.analytics.data_v1beta import BetaAnalyticsDataClient
from google.analytics.data_v1beta.types import (
    DateRange,
    Dimension,
    Metric,
    OrderBy,
    RunRealtimeReportRequest,
    RunReportRequest,
)
from google.oauth2.service_account import Credentials


class GA4ServiceError(Exception):
    pass


class GA4Service:
    """Server-side Google Analytics 4 Data API helper."""

    def __init__(self) -> None:
        self.property_id = (os.environ.get("GA4_PROPERTY_ID") or "").strip()
        credentials_json = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS_JSON")

        if not self.property_id:
            raise GA4ServiceError("GA4_PROPERTY_ID is not configured.")
        if not credentials_json:
            raise GA4ServiceError("GOOGLE_APPLICATION_CREDENTIALS_JSON is not configured.")

        try:
            credentials_info = json.loads(credentials_json)
        except json.JSONDecodeError as exc:
            raise GA4ServiceError("GOOGLE_APPLICATION_CREDENTIALS_JSON is not valid JSON.") from exc

        try:
            creds = Credentials.from_service_account_info(credentials_info)
            self.client = BetaAnalyticsDataClient(credentials=creds)
        except Exception as exc:
            raise GA4ServiceError(f"Failed to initialize GA4 client: {exc}") from exc

        self.property_path = f"properties/{self.property_id}"

    @staticmethod
    def _to_float(value: str) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _to_int(value: str) -> int:
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _fmt_date_yyyymmdd(value: str) -> str:
        if len(value) == 8 and value.isdigit():
            return f"{value[0:4]}-{value[4:6]}-{value[6:8]}"
        return value

    def _run_report(
        self,
        *,
        metrics: list[str],
        dimensions: list[str] | None = None,
        start_date: str = "30daysAgo",
        end_date: str = "today",
        limit: int = 10,
        order_by_metric: str | None = None,
    ):
        request = RunReportRequest(
            property=self.property_path,
            dimensions=[Dimension(name=d) for d in (dimensions or [])],
            metrics=[Metric(name=m) for m in metrics],
            date_ranges=[DateRange(start_date=start_date, end_date=end_date)],
            limit=limit,
        )
        if order_by_metric:
            request.order_bys = [OrderBy(metric=OrderBy.MetricOrderBy(metric_name=order_by_metric), desc=True)]
        return self.client.run_report(request)

    def _run_realtime(self, *, metrics: list[str]):
        request = RunRealtimeReportRequest(
            property=self.property_path,
            metrics=[Metric(name=m) for m in metrics],
        )
        return self.client.run_realtime_report(request)

    def get_dashboard_data(self) -> dict[str, Any]:
        try:
            summary = self._run_report(
                metrics=[
                    "activeUsers",
                    "newUsers",
                    "sessions",
                    "screenPageViews",
                    "engagementRate",
                    "bounceRate",
                    "averageSessionDuration",
                ],
                start_date="30daysAgo",
                end_date="today",
                limit=1,
            )

            summary_row = summary.rows[0].metric_values if summary.rows else []
            summary_metrics = {
                "active_users": self._to_int(summary_row[0].value) if len(summary_row) > 0 else 0,
                "new_users": self._to_int(summary_row[1].value) if len(summary_row) > 1 else 0,
                "sessions": self._to_int(summary_row[2].value) if len(summary_row) > 2 else 0,
                "page_views": self._to_int(summary_row[3].value) if len(summary_row) > 3 else 0,
                "engagement_rate": round(self._to_float(summary_row[4].value) * 100, 2) if len(summary_row) > 4 else 0.0,
                "bounce_rate": round(self._to_float(summary_row[5].value) * 100, 2) if len(summary_row) > 5 else 0.0,
                "avg_session_duration_sec": round(self._to_float(summary_row[6].value), 2) if len(summary_row) > 6 else 0.0,
            }

            realtime = self._run_realtime(metrics=["activeUsers"])
            realtime_active = 0
            if realtime.rows and realtime.rows[0].metric_values:
                realtime_active = self._to_int(realtime.rows[0].metric_values[0].value)

            trend = self._run_report(
                dimensions=["date"],
                metrics=["activeUsers", "sessions", "screenPageViews"],
                start_date="14daysAgo",
                end_date="today",
                limit=30,
            )
            trend_rows = []
            for row in trend.rows:
                trend_rows.append(
                    {
                        "date": self._fmt_date_yyyymmdd(row.dimension_values[0].value),
                        "active_users": self._to_int(row.metric_values[0].value),
                        "sessions": self._to_int(row.metric_values[1].value),
                        "page_views": self._to_int(row.metric_values[2].value),
                    }
                )

            traffic = self._run_report(
                dimensions=["sessionSourceMedium"],
                metrics=["sessions", "activeUsers"],
                order_by_metric="sessions",
                limit=10,
            )
            traffic_rows = []
            for row in traffic.rows:
                source_medium = row.dimension_values[0].value or "(direct) / (none)"
                traffic_rows.append(
                    {
                        "source_medium": source_medium,
                        "sessions": self._to_int(row.metric_values[0].value),
                        "active_users": self._to_int(row.metric_values[1].value),
                    }
                )

            geo = self._run_report(
                dimensions=["country"],
                metrics=["activeUsers", "sessions"],
                order_by_metric="activeUsers",
                limit=10,
            )
            geo_rows = []
            for row in geo.rows:
                geo_rows.append(
                    {
                        "country": row.dimension_values[0].value or "Unknown",
                        "active_users": self._to_int(row.metric_values[0].value),
                        "sessions": self._to_int(row.metric_values[1].value),
                    }
                )

            demographics_rows = []
            try:
                demographics = self._run_report(
                    dimensions=["userGender", "userAgeBracket"],
                    metrics=["activeUsers"],
                    order_by_metric="activeUsers",
                    limit=10,
                )
                for row in demographics.rows:
                    demographics_rows.append(
                        {
                            "gender": row.dimension_values[0].value or "unknown",
                            "age_bracket": row.dimension_values[1].value or "unknown",
                            "active_users": self._to_int(row.metric_values[0].value),
                        }
                    )
            except Exception:
                # Some properties may not expose demographics depending on consent/signal settings.
                demographics_rows = []

            top_pages = self._run_report(
                dimensions=["pageTitle", "pagePath"],
                metrics=["screenPageViews", "activeUsers", "engagementRate"],
                order_by_metric="screenPageViews",
                limit=10,
            )
            page_rows = []
            for row in top_pages.rows:
                page_rows.append(
                    {
                        "title": row.dimension_values[0].value or "(untitled)",
                        "path": row.dimension_values[1].value or "/",
                        "page_views": self._to_int(row.metric_values[0].value),
                        "active_users": self._to_int(row.metric_values[1].value),
                        "engagement_rate": round(self._to_float(row.metric_values[2].value) * 100, 2),
                    }
                )

            return {
                "ok": True,
                "property_id": self.property_id,
                "stream_name": "ORCEST AI LTD",
                "stream_url": "https://orcest.ai",
                "stream_id": "13652359666",
                "measurement_id": "G-3ML0EE7ZSW",
                "realtime_active_users": realtime_active,
                "summary": summary_metrics,
                "trend": trend_rows,
                "traffic_sources": traffic_rows,
                "geography": geo_rows,
                "demographics": demographics_rows,
                "top_pages": page_rows,
            }
        except Exception as exc:
            raise GA4ServiceError(f"Failed to fetch GA4 metrics: {exc}") from exc
