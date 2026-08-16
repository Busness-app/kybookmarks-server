export interface ParsedBookmark {
  url: string;
  title: string;
  notes?: string;
  folderPath: string[]; // e.g. ["Bookmarks Bar", "Dev", "Go"]
  addDate?: number;
  icon?: string;
}

export interface BookmarkFolder {
  id: string;
  name: string;
  parentId: string; // "" for root
}

export interface BookmarkItem {
  id: string;
  url: string;
  title: string;
  notes?: string;
  folderId: string;
  position: number;
  icon?: string;
  createdAt: number;
  updatedAt: number;
}

// Parse standard Netscape Bookmark HTML file (used by all major browsers)
export function parseNetscapeBookmarkHTML(htmlContent: string): ParsedBookmark[] {
  const parser = new DOMParser();
  const doc = parser.parseFromString(htmlContent, 'text/html');
  const results: ParsedBookmark[] = [];

  function traverse(node: Element, currentPath: string[]) {
    for (let i = 0; i < node.children.length; i++) {
      const child = node.children[i];
      const tag = child.tagName.toUpperCase();

      if (tag === 'DT') {
        const h3 = child.querySelector(':scope > H3');
        const dl = child.querySelector(':scope > DL');
        const a = child.querySelector(':scope > A');

        if (h3 && dl) {
          const folderName = h3.textContent?.trim() || 'Folder';
          // limit path depth to max 5
          const newPath = currentPath.length < 5 ? [...currentPath, folderName] : currentPath;
          traverse(dl, newPath);
        } else if (a) {
          const href = a.getAttribute('HREF') || a.getAttribute('href') || '';
          if (href.startsWith('http://') || href.startsWith('https://')) {
            const title = a.textContent?.trim() || href;
            const icon = a.getAttribute('ICON') || a.getAttribute('icon') || '';
            const addDate = parseInt(a.getAttribute('ADD_DATE') || '0', 10);
            
            // Check for next DD tag for notes
            let notes = '';
            const nextEl = child.nextElementSibling;
            if (nextEl && nextEl.tagName.toUpperCase() === 'DD') {
              notes = nextEl.textContent?.trim() || '';
            }

            results.push({
              url: href,
              title,
              notes,
              folderPath: currentPath.length > 0 ? currentPath : ['Other Bookmarks'],
              addDate: addDate > 0 ? addDate * 1000 : Date.now(),
              icon: icon.startsWith('data:') ? icon : undefined,
            });
          }
        }
      } else if (tag === 'DL') {
        traverse(child, currentPath);
      }
    }
  }

  const rootDL = doc.querySelector('DL');
  if (rootDL) {
    traverse(rootDL, []);
  } else {
    // Fallback: search all <a> tags
    const links = doc.querySelectorAll('a[href^="http"]');
    links.forEach((a) => {
      const href = a.getAttribute('href') || '';
      results.push({
        url: href,
        title: a.textContent?.trim() || href,
        folderPath: ['Other Bookmarks'],
        addDate: Date.now(),
      });
    });
  }

  return results;
}

// Generate Netscape Bookmark HTML export string
export function exportToNetscapeHTML(
  folders: BookmarkFolder[],
  bookmarks: BookmarkItem[]
): string {
  let html = `<!DOCTYPE NETSCAPE-Bookmark-file-1>
<!-- This is an automatically generated file.
     It will be read and overwritten.
     DO NOT EDIT! -->
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<TITLE>Bookmarks</TITLE>
<H1>Bookmarks</H1>
<DL><p>
`;

  // Build folder hierarchy tree
  const folderMap = new Map<string, BookmarkFolder>();
  const childrenMap = new Map<string, BookmarkFolder[]>();

  folders.forEach((f) => {
    folderMap.set(f.id, f);
    const pId = f.parentId || '';
    if (!childrenMap.has(pId)) childrenMap.set(pId, []);
    childrenMap.get(pId)!.push(f);
  });

  const bmsByFolder = new Map<string, BookmarkItem[]>();
  bookmarks.forEach((bm) => {
    const fId = bm.folderId || '';
    if (!bmsByFolder.has(fId)) bmsByFolder.set(fId, []);
    bmsByFolder.get(fId)!.push(bm);
  });

  function renderFolder(folderId: string, indent: string) {
    // Render bookmarks in this folder
    const bms = bmsByFolder.get(folderId) || [];
    bms.forEach((b) => {
      const addDate = Math.floor(b.createdAt / 1000);
      const iconAttr = b.icon ? ` ICON="${b.icon}"` : '';
      html += `${indent}<DT><A HREF="${escapeHTML(b.url)}" ADD_DATE="${addDate}"${iconAttr}>${escapeHTML(b.title)}</A>\n`;
      if (b.notes) {
        html += `${indent}<DD>${escapeHTML(b.notes)}\n`;
      }
    });

    // Render subfolders
    const subfolders = childrenMap.get(folderId) || [];
    subfolders.forEach((sub) => {
      html += `${indent}<DT><H3 ADD_DATE="${Math.floor(Date.now() / 1000)}">${escapeHTML(sub.name)}</H3>\n`;
      html += `${indent}<DL><p>\n`;
      renderFolder(sub.id, indent + '    ');
      html += `${indent}</DL><p>\n`;
    });
  }

  // Render root level
  renderFolder('', '    ');
  html += `</DL><p>\n`;
  return html;
}

function escapeHTML(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
