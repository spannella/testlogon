import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/PageHeader";
import { CalendarView } from "./CalendarView";
import { CalendarsManager } from "./CalendarsManager";
import { BookingLinks } from "./BookingLinks";
import { CalendarSharing } from "./CalendarSharing";
import { CalendarSettings } from "./CalendarSettings";
import { GoogleCalendarIntegration } from "./GoogleCalendarIntegration";
import { isGoogleCalendarSyncEnabled } from "@/lib/featureFlags";

export default function CalendarPage() {
  const googleSyncEnabled = isGoogleCalendarSyncEnabled();

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Calendar"
        description="Manage events, schedules, and booking links"
      />

      <Tabs defaultValue="calendars">
        <TabsList>
          <TabsTrigger value="calendars">Calendars</TabsTrigger>
          <TabsTrigger value="calendar">View</TabsTrigger>
          <TabsTrigger value="booking">Booking Links</TabsTrigger>
          <TabsTrigger value="sharing">Sharing</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
          {googleSyncEnabled && <TabsTrigger value="integrations">Integrations</TabsTrigger>}
        </TabsList>
        <TabsContent value="calendars">
          <CalendarsManager />
        </TabsContent>
        <TabsContent value="calendar">
          <CalendarView />
        </TabsContent>
        <TabsContent value="booking">
          <BookingLinks />
        </TabsContent>
        <TabsContent value="sharing">
          <CalendarSharing />
        </TabsContent>
        <TabsContent value="settings">
          <CalendarSettings />
        </TabsContent>
        {googleSyncEnabled && (
          <TabsContent value="integrations">
            <GoogleCalendarIntegration />
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}
