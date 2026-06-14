import { requireSession, getCurrentUser } from "@/lib/auth";

export const dynamic = "force-dynamic";

export default async function Dashboard() {
  // Redirects to sign-in if there is no session. Returns the FULL payload,
  // including the typed `userId` from onSignIn.
  const session = await requireSession("/app/dashboard");

  // Standardized { sub, email, name } — the common read path.
  const user = await getCurrentUser();

  return (
    <main>
      <h1>Hello {user?.name ?? user?.sub}</h1>
      <p>6away id: {session.sub}</p>
      <p>local user id: {session.userId}</p>
      <a href="/api/auth/signout">Sign out</a>
    </main>
  );
}
