import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/PageHeader";
import { CalendarView } from "./CalendarView";
import { BookingLinks } from "./BookingLinks";
import { CalendarSharing } from "./CalendarSharing";
import { CalendarSettings } from "./CalendarSettings";

export default function CalendarPage() {
  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Calendar"
        description="Manage events, schedules, and booking links"
      />

      <Tabs defaultValue="calendar">
        <TabsList>
          <TabsTrigger value="calendar">Calendar</TabsTrigger>
          <TabsTrigger value="booking">Booking Links</TabsTrigger>
          <TabsTrigger value="sharing">Sharing</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>
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
      </Tabs>
    </div>
  );
}
