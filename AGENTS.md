<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## Application architecture

- Keep application pages on TanStack Start file-based routes and split reusable, domain-specific UI and database operations into feature modules; this preserves SSR/runtime compatibility and makes the student-management workflows approachable to maintain.
- Use Lovable Cloud authentication, role-gated Row Level Security, and browser clients for ordinary administrator CRUD; this keeps student records protected by the database rather than by navigation alone.
