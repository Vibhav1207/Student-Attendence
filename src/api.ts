import type {
  Notification,
  Academic,
  AuthResponse,
  ClassInfo,
  ErpImport,
  EventReport,
  FinalReport,
  LeaveApplication,
  Lecture,
  Phase,
  SkippedDay,
  StudentListItem,
  SubjectSummary,
  User,
} from "./types";

const TOKEN_KEY = "attendance_portal_token";

/**
 * The login is kept per browser tab (sessionStorage), so a student and a coordinator can be
 * logged in side by side in two tabs without one login replacing the other.
 * It survives a page refresh; closing the tab logs out.
 */
export const tokenStore = {
  get: () => sessionStorage.getItem(TOKEN_KEY),
  set: (token: string) => {
    sessionStorage.setItem(TOKEN_KEY, token);
    localStorage.removeItem(TOKEN_KEY); // clean up the old shared login from earlier versions
  },
  clear: () => {
    sessionStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(TOKEN_KEY);
  },
};

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

type RequestOptions = {
  method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  body?: unknown;
};

async function send(path: string, options: RequestOptions = {}): Promise<Response> {
  const token = tokenStore.get();
  const headers: Record<string, string> = {};

  let body: BodyInit | undefined;
  if (options.body instanceof FormData) {
    body = options.body; // the browser sets the multipart boundary itself
  } else if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.body);
  }
  if (token) headers.Authorization = `Bearer ${token}`;

  let response: Response;
  try {
    response = await fetch(path, { method: options.method ?? "GET", headers, body });
  } catch {
    throw new ApiError(0, "Can't reach the server. Make sure the backend is running.");
  }

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    const message = (data as { error?: string }).error;
    throw new ApiError(
      response.status,
      message ??
        (response.status >= 500
          ? "The server isn't responding. Make sure the backend is running."
          : "Something went wrong.")
    );
  }
  return response;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const response = await send(path, options);
  return (await response.json()) as T;
}

/** Opens a file from the API in a new tab (the request needs the login token). */
async function openFile(path: string) {
  const tab = window.open("", "_blank");
  try {
    const response = await send(path);
    const url = URL.createObjectURL(await response.blob());
    if (tab) tab.location.href = url;
    else window.location.href = url;
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  } catch (err) {
    tab?.close();
    throw err;
  }
}

/** Downloads a file from the API with the name the server gives it. */
async function downloadFile(path: string, fallbackName: string, method: "GET" | "POST" = "GET") {
  const response = await send(path, { method });
  const disposition = response.headers.get("Content-Disposition") ?? "";
  const name = /filename="([^"]+)"/.exec(disposition)?.[1] ?? fallbackName;
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

export type FacultySignup = {
  name: string;
  email: string;
  password: string;
  designation: string;
  facultyCode: string;
  classes: string[];
};

export type PreviewResult = {
  lectures: Lecture[];
  skipped: SkippedDay[];
  subjects: SubjectSummary[];
  phases: Phase[];
  counted: boolean;
};

export type Calculation = {
  counted: boolean;
  phases: Phase[];
  subjects: SubjectSummary[];
};

export type ErpImportResult = {
  importId: string;
  replaced: boolean;
  label: string;
  asOf: string;
  division: string;
  periodFrom: string | null;
  periodTo: string | null;
  students: number;
  subjects: number;
  unmatchedSubjects: string[];
  unknownPrns: string[];
  unknownCount: number;
  missingStudents: number;
};

export const api = {
  classes: () => request<{ classes: ClassInfo[] }>("/api/classes"),

  login: (identifier: string, password: string) =>
    request<AuthResponse>("/api/auth/login", { method: "POST", body: { identifier, password } }),

  signup: (payload: FacultySignup) =>
    request<AuthResponse>("/api/auth/signup", { method: "POST", body: payload }),

  me: () => request<{ user: User }>("/api/auth/me"),

  changePassword: (currentPassword: string, newPassword: string) =>
    request<{ user: User }>("/api/auth/change-password", {
      method: "POST",
      body: { currentPassword, newPassword },
    }),

  academic: () => request<Academic>("/api/academic"),

  preview: (startDate: string, endDate: string, kind: string) =>
    request<PreviewResult>("/api/applications/preview", {
      method: "POST",
      body: { startDate, endDate, kind },
    }),

  submitApplication: (form: FormData) =>
    request<{ application: LeaveApplication }>("/api/applications", { method: "POST", body: form }),

  applications: (classId?: string) =>
    request<{ applications: LeaveApplication[] }>(
      classId ? `/api/applications?classId=${encodeURIComponent(classId)}` : "/api/applications"
    ),

  calculation: (id: string) => request<Calculation>(`/api/applications/${id}/calculation`),

  studentMarkRead: (id: string) =>
    request<{ ok: boolean }>(`/api/applications/${id}/student-read`, { method: "PATCH" }),

  sendReminder: (id: string) =>
    request<{ ok: boolean; eventName: string }>(`/api/applications/${id}/reminder`, { method: "POST" }),

  uploadCertificate: (id: string, file: File) => {
    const form = new FormData();
    form.append("file", file);
    return request<{ application: import("./types").LeaveApplication }>(
      `/api/applications/${id}/upload-certificate`,
      { method: "PATCH", body: form }
    );
  },

  notifications: () =>
    request<{ unread: number; notifications: Notification[] }>("/api/notifications"),

  markNotificationRead: (id: string) =>
    request<{ ok: boolean }>(`/api/notifications/${id}/read`, { method: "PATCH" }),

  markAllNotificationsRead: () =>
    request<{ ok: boolean }>("/api/notifications/read-all", { method: "PATCH" }),

  markRead: (id: string) =>
    request<{ application: LeaveApplication }>(`/api/applications/${id}/read`, { method: "PATCH" }),

  review: (id: string, status: "approved" | "rejected", remark: string) =>
    request<{ application: LeaveApplication }>(`/api/applications/${id}/review`, {
      method: "PATCH",
      body: { status, remark },
    }),

  openDocument: (applicationId: string, documentId: string) =>
    openFile(`/api/applications/${applicationId}/documents/${documentId}`),

  students: (classId: string) =>
    request<{ students: StudentListItem[] }>(`/api/students/${encodeURIComponent(classId)}`),

  resetPassword: (prn: string) =>
    request<{ prn: string; name: string; password: string }>(
      `/api/students/${encodeURIComponent(prn)}/reset-password`,
      { method: "POST" }
    ),

  /** Creates new starting passwords for students who haven't logged in yet, and downloads them. */
  downloadPasswords: (classId: string) =>
    downloadFile(
      `/api/reports/passwords/${encodeURIComponent(classId)}`,
      `starting_passwords_${classId}.xlsx`,
      "POST"
    ),

  // ERP attendance import (class coordinator)
  downloadErpTemplate: (classId: string) =>
    downloadFile(`/api/erp/template/${encodeURIComponent(classId)}`, `ERP_attendance_template_${classId}.xlsx`),

  importErp: (classId: string, form: FormData) =>
    request<ErpImportResult>(`/api/erp/import/${encodeURIComponent(classId)}`, { method: "POST", body: form }),

  erpImports: (classId: string) =>
    request<{ imports: ErpImport[] }>(`/api/erp/imports/${encodeURIComponent(classId)}`),

  deleteErpImport: (id: string) => request<{ deleted: boolean }>(`/api/erp/imports/${id}`, { method: "DELETE" }),

  // Report 1: event attendance
  eventReport: (classId: string) => request<EventReport>(`/api/reports/event/${encodeURIComponent(classId)}`),

  downloadEventReport: (classId: string) =>
    downloadFile(`/api/reports/event/${encodeURIComponent(classId)}/xlsx`, `Event_attendance_${classId}.xlsx`),

  // Report 2: final attendance (ERP + events)
  finalReport: (classId: string, importId?: string) =>
    request<FinalReport>(
      `/api/reports/final/${encodeURIComponent(classId)}${importId ? `?importId=${importId}` : ""}`
    ),

  downloadFinalReport: (classId: string, importId?: string) =>
    downloadFile(
      `/api/reports/final/${encodeURIComponent(classId)}/xlsx${importId ? `?importId=${importId}` : ""}`,
      `Final_attendance_${classId}.xlsx`
    ),

  /** One detention list for every class the faculty member can see (HoD: whole department). */
  downloadDepartmentDetentionList: () =>
    downloadFile("/api/reports/detention-list", "Detention_List_CSE.docx"),

  downloadDetentionList: (classId: string, importId?: string) =>
    downloadFile(
      `/api/reports/final/${encodeURIComponent(classId)}/detention-list${importId ? `?importId=${importId}` : ""}`,
      `Detention_List_${classId}.docx`
    ),
};
