import { useState } from "react";
import {
  useListRoleEvents,
  useGetRoleStats,
  useListGuilds,
} from "@workspace/api-client-react";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import {
  Shield,
  Users,
  TrendingUp,
  TrendingDown,
  Search,
  ChevronLeft,
  ChevronRight,
  Activity,
  Crown,
} from "lucide-react";

function formatDate(d: Date | string) {
  return new Date(d).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function ActionBadge({ action }: { action: string }) {
  return action === "assigned" ? (
    <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20">
      ↑ assigned
    </Badge>
  ) : (
    <Badge className="bg-red-500/20 text-red-400 border-red-500/30 hover:bg-red-500/20">
      ↓ removed
    </Badge>
  );
}

export default function Dashboard() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [action, setAction] = useState<string>("all");
  const [guildId, setGuildId] = useState<string>("all");

  const limit = 25;

  const { data: guildsData } = useListGuilds();
  const { data: stats, isLoading: statsLoading } = useGetRoleStats({
    guildId: guildId === "all" ? undefined : guildId,
  });
  const { data: events, isLoading: eventsLoading } = useListRoleEvents({
    page,
    limit,
    guildId: guildId === "all" ? undefined : guildId,
    action: action === "all" ? undefined : (action as "assigned" | "removed"),
    search: search || undefined,
  });

  const totalPages = events ? Math.ceil(events.total / limit) : 0;

  function handleSearch() {
    setSearch(searchInput);
    setPage(1);
  }

  function handleActionChange(val: string) {
    setAction(val);
    setPage(1);
  }

  function handleGuildChange(val: string) {
    setGuildId(val);
    setPage(1);
    setSearch("");
    setSearchInput("");
  }

  return (
    <div className="min-h-screen bg-[#1a1b1e] text-gray-100">
      {/* Header */}
      <div className="border-b border-white/10 bg-[#141517]">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-indigo-500 flex items-center justify-center">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-white leading-none">
              Role Tracker
            </h1>
            <p className="text-xs text-gray-400 mt-0.5">
              Discord role assignment history
            </p>
          </div>

          {/* Guild selector */}
          {guildsData && guildsData.guilds.length > 1 && (
            <div className="ml-auto">
              <Select value={guildId} onValueChange={handleGuildChange}>
                <SelectTrigger className="w-52 bg-white/5 border-white/10 text-gray-200 text-sm">
                  <SelectValue placeholder="All guilds" />
                </SelectTrigger>
                <SelectContent className="bg-[#2b2d31] border-white/10 text-gray-200">
                  <SelectItem value="all">All guilds</SelectItem>
                  {guildsData.guilds.map((g) => (
                    <SelectItem key={g.id} value={g.id}>
                      {g.id}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">
        {/* Stat cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <Card className="bg-white/5 border-white/10">
            <CardContent className="p-5 flex items-center gap-4">
              <div className="w-10 h-10 rounded-lg bg-indigo-500/20 flex items-center justify-center">
                <Activity className="w-5 h-5 text-indigo-400" />
              </div>
              <div>
                <p className="text-xs text-gray-400 uppercase tracking-wide">
                  Total Events
                </p>
                <p className="text-2xl font-bold text-white">
                  {statsLoading ? "—" : (stats?.totalEvents ?? 0).toLocaleString()}
                </p>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-white/5 border-white/10">
            <CardContent className="p-5 flex items-center gap-4">
              <div className="w-10 h-10 rounded-lg bg-emerald-500/20 flex items-center justify-center">
                <TrendingUp className="w-5 h-5 text-emerald-400" />
              </div>
              <div>
                <p className="text-xs text-gray-400 uppercase tracking-wide">
                  Roles Assigned
                </p>
                <p className="text-2xl font-bold text-emerald-400">
                  {statsLoading ? "—" : (stats?.totalAssigned ?? 0).toLocaleString()}
                </p>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-white/5 border-white/10">
            <CardContent className="p-5 flex items-center gap-4">
              <div className="w-10 h-10 rounded-lg bg-red-500/20 flex items-center justify-center">
                <TrendingDown className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <p className="text-xs text-gray-400 uppercase tracking-wide">
                  Roles Removed
                </p>
                <p className="text-2xl font-bold text-red-400">
                  {statsLoading ? "—" : (stats?.totalRemoved ?? 0).toLocaleString()}
                </p>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Top mods + Top roles */}
        {stats && (stats.topMods.length > 0 || stats.topRoles.length > 0) && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {stats.topMods.length > 0 && (
              <Card className="bg-white/5 border-white/10">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium text-gray-300 flex items-center gap-2">
                    <Crown className="w-4 h-4 text-yellow-400" />
                    Top Moderators
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-0 space-y-2">
                  {stats.topMods.slice(0, 5).map((mod, i) => (
                    <div
                      key={mod.executorId}
                      className="flex items-center justify-between text-sm"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="text-gray-500 w-4 shrink-0">
                          {i + 1}.
                        </span>
                        <span className="text-gray-200 truncate">
                          {mod.executorTag}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0 ml-2">
                        <span className="text-emerald-400 text-xs">
                          +{mod.assigned}
                        </span>
                        <span className="text-red-400 text-xs">
                          −{mod.removed}
                        </span>
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {stats.topRoles.length > 0 && (
              <Card className="bg-white/5 border-white/10">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium text-gray-300 flex items-center gap-2">
                    <Users className="w-4 h-4 text-indigo-400" />
                    Most Assigned Roles
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-0 space-y-2">
                  {stats.topRoles.slice(0, 5).map((role, i) => (
                    <div
                      key={role.roleName}
                      className="flex items-center justify-between text-sm"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="text-gray-500 w-4 shrink-0">
                          {i + 1}.
                        </span>
                        <span className="text-gray-200 truncate">
                          {role.roleName}
                        </span>
                      </div>
                      <span className="text-indigo-400 text-xs shrink-0 ml-2">
                        {role.times}×
                      </span>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}
          </div>
        )}

        <Separator className="bg-white/10" />

        {/* Events table */}
        <div className="space-y-3">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 min-w-48">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <Input
                className="pl-9 bg-white/5 border-white/10 text-gray-200 placeholder:text-gray-500 focus-visible:ring-indigo-500"
                placeholder="Search user or role…"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSearch()}
              />
            </div>
            <Button
              variant="secondary"
              className="bg-white/10 text-gray-200 hover:bg-white/15 border-white/10"
              onClick={handleSearch}
            >
              Search
            </Button>
            <Select value={action} onValueChange={handleActionChange}>
              <SelectTrigger className="w-36 bg-white/5 border-white/10 text-gray-200">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-[#2b2d31] border-white/10 text-gray-200">
                <SelectItem value="all">All actions</SelectItem>
                <SelectItem value="assigned">Assigned</SelectItem>
                <SelectItem value="removed">Removed</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Card className="bg-white/5 border-white/10 overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="border-white/10 hover:bg-transparent">
                  <TableHead className="text-gray-400 font-medium">
                    When
                  </TableHead>
                  <TableHead className="text-gray-400 font-medium">
                    Action
                  </TableHead>
                  <TableHead className="text-gray-400 font-medium">
                    Moderator
                  </TableHead>
                  <TableHead className="text-gray-400 font-medium">
                    Target
                  </TableHead>
                  <TableHead className="text-gray-400 font-medium">
                    Role
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {eventsLoading ? (
                  Array.from({ length: 8 }).map((_, i) => (
                    <TableRow
                      key={i}
                      className="border-white/5 hover:bg-white/5"
                    >
                      {Array.from({ length: 5 }).map((_, j) => (
                        <TableCell key={j}>
                          <div className="h-4 bg-white/10 rounded animate-pulse w-24" />
                        </TableCell>
                      ))}
                    </TableRow>
                  ))
                ) : events?.data.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={5}
                      className="text-center text-gray-500 py-12"
                    >
                      No events found
                    </TableCell>
                  </TableRow>
                ) : (
                  events?.data.map((event) => (
                    <TableRow
                      key={event.id}
                      className="border-white/5 hover:bg-white/5 transition-colors"
                    >
                      <TableCell className="text-gray-400 text-sm whitespace-nowrap">
                        {formatDate(event.assignedAt)}
                      </TableCell>
                      <TableCell>
                        <ActionBadge action={event.action} />
                      </TableCell>
                      <TableCell className="text-gray-200 text-sm">
                        {event.executorTag}
                      </TableCell>
                      <TableCell className="text-gray-200 text-sm">
                        {event.targetTag}
                      </TableCell>
                      <TableCell className="text-indigo-300 text-sm font-medium">
                        {event.roleName}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </Card>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between text-sm text-gray-400">
              <span>
                {events
                  ? `${(page - 1) * limit + 1}–${Math.min(page * limit, events.total)} of ${events.total.toLocaleString()}`
                  : ""}
              </span>
              <div className="flex items-center gap-1">
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 text-gray-400 hover:text-white hover:bg-white/10"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => p - 1)}
                >
                  <ChevronLeft className="w-4 h-4" />
                </Button>
                <span className="px-2">
                  {page} / {totalPages}
                </span>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 text-gray-400 hover:text-white hover:bg-white/10"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  <ChevronRight className="w-4 h-4" />
                </Button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
