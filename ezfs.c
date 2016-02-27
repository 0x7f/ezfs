#include <assert.h>
#include <errno.h>
#include <fuse.h>
#include <json.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if __linux__
#include <linux/limits.h>
#elif __APPLE__
#include <sys/syslimits.h>
#else
#error "Unsupported platform."
#endif

#define MAX_TREES 10

struct ezfs_tree_s {
    const char *name;
    json_object *json;
    json_object *root;
};

typedef struct ezfs_tree_s *ezfs_tree_t;

struct ezfs_context_s {
    // TODO: switch to dynamic array/list
    struct ezfs_tree_s trees[MAX_TREES];
};

typedef struct ezfs_context_s *ezfs_context_t;

static int ezfs_load_tree_from_json(ezfs_tree_t tree, json_object *json) {
    json_bool r;

    tree->json = json;

    assert(json_object_is_type(json, json_type_object));

    json_object *tree_name_obj;
    r = json_object_object_get_ex(json, "name", &tree_name_obj);
    assert(r && json_object_is_type(tree_name_obj, json_type_string));
    const char *tree_name = json_object_get_string(tree_name_obj);
    assert(tree_name != NULL && *tree_name);
    tree->name = strdup(tree_name);

    json_object *tree_root;
    r = json_object_object_get_ex(json, "tree", &tree_root);
    assert(r && tree_root && json_object_is_type(tree_root, json_type_object));
    tree->root = tree_root;

    json_object *type_obj;
    r = json_object_object_get_ex(tree_root, "type", &type_obj);
    assert(r && tree_root && json_object_is_type(type_obj, json_type_string));
    assert(0 == strcmp("folder", json_object_get_string(type_obj)));

    /*
    char* pretty_json = json_object_to_json_string_ext(json,
    JSON_C_TO_STRING_PRETTY);
    printf("successfully loaded the db:\n%s\n", pretty_json);
    free(pretty_json);
    */

    return 0;
}

static ezfs_tree_t ezfs_find_tree_by_name(ezfs_context_t ctx, const char *name, int name_len) {
    for (int i = 0; i < MAX_TREES; ++i) {
        ezfs_tree_t tree = &(ctx->trees[i]);
        if (tree->name && strlen(tree->name) == name_len &&
            strncmp(tree->name, name, name_len) == 0) {
            return tree;
        }
    }
    return NULL;
}

static json_object *ezfs_find_child_for_name(json_object *children, const char *name,
                                             size_t name_len) {
    assert(json_object_is_type(children, json_type_array));

    int num_children = json_object_array_length(children);
    for (int i = 0; i < num_children; ++i) {
        json_object *child = json_object_array_get_idx(children, i);
        if (!child || !json_object_is_type(child, json_type_object)) {
            fprintf(stderr, "Child is not an object.\n");
            return NULL;
        }

        json_object *name_obj;
        json_bool r = json_object_object_get_ex(child, "name", &name_obj);
        if (!r || !json_object_is_type(name_obj, json_type_string)) {
            fprintf(stderr, "Child has no name.\n");
            return NULL;
        }

        const char *name_str = json_object_get_string(name_obj);
        if (strlen(name_str) == name_len && strncmp(name_str, name, name_len) == 0) {
            return child;
        }
    }

    return NULL;
}

// return value is depth. 0 for root, 1 for tree root. negative for error or not found.
static int ezfs_node_for_path(ezfs_context_t ctx, const char *path, ezfs_tree_t *tree,
                              json_object **node) {
    size_t path_len = strlen(path);
    assert(path_len && path[0] == '/');

    printf("ezfs_node_for_path(%s) %zu\n", path, path_len);

    *tree = NULL;
    *node = NULL;

    const char *next_slash = strchr(path + 1, '/');
    if (!next_slash && path_len <= 1) { // path is "/"
        return 0;
    }

    const char *tree_name = path + 1;
    size_t name_len = next_slash ? (next_slash - tree_name) : (path_len - 1);
    printf("=== (%d) %s\n", name_len, tree_name);
    *tree = ezfs_find_tree_by_name(ctx, tree_name, name_len);
    if (!*tree) {
        return -1;
    }

    // either no further slash or found slash is at end
    if (!next_slash || (next_slash + 1 == path + path_len)) {
        *node = (*tree)->root;
        return 1;
    }

    int level = 2;
    json_object *curr_node = (*tree)->root;
    while (next_slash && *next_slash) {
        const char *begin = next_slash + 1;
        const char *end = strchr(begin, '/');
        if (!end) { // leaf node in path
            end = &path[path_len];
        }
        size_t len = end - begin;
        assert(len > 0);

        json_bool r;

        json_object *children;
        r = json_object_object_get_ex(curr_node, "children", &children);
        if (!r || !json_object_is_type(children, json_type_array)) {
            fprintf(stderr, "Node has no children.\n");
            return -1;
        }

        json_object *child = ezfs_find_child_for_name(children, begin, len);
        if (!child) {
            fprintf(stderr, "Child not found for name %s(%zu).\n", begin, len);
            return -1;
        }

        // end points to end of path or only slash left at end
        if (end == path + path_len || (*end == '/' && end + 1 == path + path_len)) {
            *node = child;
            return level;
        }

        next_slash = end;
        curr_node = child;
        ++level;
    }

    return -1;
}

int ezfs_resolve(ezfs_context_t ctx, const char *path, char *resolved, size_t len, int *file_type) {
    if (strcmp(path, "/") == 0) {
        *file_type = S_IFDIR;
        strncpy(resolved, "/", len);
        return 0;
    }

    printf(">>> ezfs_resolve(%s)\n", path);

    ezfs_tree_t tree;
    json_object *node;
    int rc = ezfs_node_for_path(ctx, path, &tree, &node);
    if (rc < 0) {
        return -ENOENT;
    }

    // no tree for given path
    if (!tree) {
        return -ENOENT;
    }

    // top-level with tree names, also mapped to /
    if (!node) {
        printf(">>> found tree but no node for %s\n", path);
        *file_type = S_IFDIR;
        strncpy(resolved, "/", len);
        return 0;
    }

    json_bool r;

    json_object *type;
    r = json_object_object_get_ex(node, "type", &type);
    if (!r || !json_object_is_type(type, json_type_string)) {
        fprintf(stderr, "Node for path %s has no valid attribute.\n", path);
        return -ENOENT;
    }

    const char *type_str = json_object_get_string(type);
    if (strcmp(type_str, "folder") == 0) {
        *file_type = S_IFDIR;
        strncpy(resolved, "/", len);
        return 0;
    }

    if (strcmp(type_str, "file") != 0) {
        fprintf(stderr, "Node for path %s has no valid type.\n", path);
        return -ENOENT;
    }

    json_object *properties;
    r = json_object_object_get_ex(node, "properties", &properties);
    if (!r || !json_object_is_type(properties, json_type_object)) {
        fprintf(stderr, "Node for path %s has no properties object.\n", path);
        return -ENOENT;
    }

    json_object *file_path;
    r = json_object_object_get_ex(properties, "file.path", &file_path);
    if (!r || !json_object_is_type(file_path, json_type_string)) {
        fprintf(stderr, "Node for path %s has no file.path property.\n", path);
        return -ENOENT;
    }

    *file_type = S_IFREG;
    strncpy(resolved, json_object_get_string(file_path), len);
    return 0;
}

static void *ezfs_fuse_init(struct fuse_conn_info *conn) {
    printf("ezfs_fuse_init()\n");

    int rc;
    ezfs_context_t ctx = calloc(1, sizeof(struct ezfs_context_s));

    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "The environment variable HOME is not set!\n");
        exit(1);
    }

    // TODO: collect all json files in config dir
    char tree1_fname[PATH_MAX];
    rc = snprintf(tree1_fname, PATH_MAX, "%s/.ezfs/trees/photos_by_country.json", home);
    if (rc < 0) {
        fprintf(stderr, "Unable to allocate memory\n");
        exit(1);
    }

    json_object *json = json_object_from_file(tree1_fname);
    if (!json) {
        fprintf(stderr, "Unable to load json from %s\n", tree1_fname);
        exit(1);
    }

    rc = ezfs_load_tree_from_json(&ctx->trees[0], json);
    if (rc < 0) {
        fprintf(stderr, "Error while loading tree from json %s\n", tree1_fname);
        exit(1);
    }

    return ctx;
}

static void ezfs_fuse_destroy(void *conn) {
    printf("ezfs_fuse_destroy()\n");

    ezfs_context_t ctx = fuse_get_context()->private_data;

    for (int i = 0; i < MAX_TREES; ++i) {
        if (ctx->trees[i].json) {
            // decrements the ref count
            json_object_put(ctx->trees[i].json);
        }
    }

    free(ctx);
}

static int ezfs_fuse_getattr(const char *path, struct stat *stbuf) {
    printf("ezfs_fuse_getattr(%s)\n", path);

    memset(stbuf, 0, sizeof(struct stat));

    ezfs_context_t ctx = fuse_get_context()->private_data;

    int type = 0;
    char resolved_path[PATH_MAX];
    int rc = ezfs_resolve(ctx, path, resolved_path, PATH_MAX, &type);
    if (rc < 0) {
        fprintf(stderr, "ezfs_resolve failed for %s\n", path);
        return rc;
    }

    resolved_path[PATH_MAX - 1] = '\0';

    if (type & S_IFREG) {
        if (stat(resolved_path, stbuf) != 0) {
            fprintf(stderr, "unable to call stat for resolved path %s for %s\n", resolved_path,
                    path);
            return -ENOENT;
        }
        assert(stbuf->st_mode & S_IFREG);
        stbuf->st_mode &= ~S_IFMT; // unset all file type bits
        stbuf->st_mode |= S_IFREG; // enforce regular file
        stbuf->st_mode &= ~0777;   // disable all file attributes
        stbuf->st_mode |= 0444;    // enable read-only
    } else if (type & S_IFDIR) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else {
        assert(0 && "unsupported file type.");
        return -EINVAL;
    }

    return 0;
}

static int ezfs_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
                             struct fuse_file_info *fi) {
    printf("ezfs_fuse_readdir(%s)\n", path);

    (void)offset;
    (void)fi;

    assert(offset == 0);

    ezfs_context_t ctx = fuse_get_context()->private_data;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    if (strcmp(path, "/") == 0) {
        for (int i = 0; i < MAX_TREES; ++i) {
            if (ctx->trees[i].name) {
                filler(buf, ctx->trees[i].name, NULL, 0);
            }
        }
        return 0;
    }

    ezfs_tree_t tree;
    json_object *node;
    int rc = ezfs_node_for_path(ctx, path, &tree, &node);
    if (rc < 0) {
        fprintf(stderr, "Error while retrieving node for path\n");
        return -ENOENT;
    }

    if (!tree) {
        fprintf(stderr, "No tree found for %s?!?\n", path);
        return -ENOENT;
    }

    if (!node) {
        fprintf(stderr, "No node found for %s?!?\n", path);
        return -ENOENT;
    }

    json_bool r;

    json_object *children;
    r = json_object_object_get_ex(node, "children", &children);
    if (!r || !json_object_is_type(children, json_type_array)) {
        fprintf(stderr, "Node has no children.\n");
        return -EINVAL;
    }

    int num_children = json_object_array_length(children);
    for (int i = 0; i < num_children; ++i) {
        json_object *child = json_object_array_get_idx(children, i);
        if (!child || !json_object_is_type(child, json_type_object)) {
            fprintf(stderr, "Child is not an object.\n");
            continue;
        }

        json_object *name_obj;
        json_bool r = json_object_object_get_ex(child, "name", &name_obj);
        if (!r || !json_object_is_type(name_obj, json_type_string)) {
            fprintf(stderr, "Child has no name.\n");
            continue;
        }

        filler(buf, json_object_get_string(name_obj), NULL, 0);
    }

    return 0;
}

static int ezfs_fuse_open(const char *path, struct fuse_file_info *fi) {
    printf("ezfs_fuse_open(%s)\n", path);

    ezfs_context_t ctx = fuse_get_context()->private_data;

    if ((fi->flags & 3) != O_RDONLY) {
        return -EACCES;
    }

    int type = 0;
    char resolved_path[PATH_MAX];
    int rc = ezfs_resolve(ctx, path, resolved_path, PATH_MAX, &type);
    if (rc < 0) {
        return rc;
    }

    resolved_path[PATH_MAX - 1] = '\0';

    if (!(type & S_IFREG)) {
        return -EINVAL;
    }

    int fd = open(resolved_path, fi->flags);
    if (fd < 0) {
        fprintf(stderr, "unable to open \"%s\" (fd=%d), reason: %d - %s\n", path, fd, errno,
                strerror(errno));
        return -EACCES;
    }

    fi->fh = fd;

    return 0;
}

static int ezfs_fuse_read(const char *path, char *buf, size_t size, off_t offset,
                          struct fuse_file_info *fi) {
    printf("ezfs_fuse_read(%s)\n", path);

    assert(fi && fi->fh > 0);
    return pread(fi->fh, buf, size, offset);
}

static int ezfs_fuse_release(const char *path, struct fuse_file_info *fi) {
    printf("ezfs_fuse_release(%s)\n", path);
    assert(fi && fi->fh > 0);
    int res = close(fi->fh);
    fi->fh = 0;
    return res;
}

int main(int argc, char **argv) {
    struct fuse_operations operations;
    memset(&operations, 0, sizeof(struct fuse_operations));
    operations.init = ezfs_fuse_init;
    operations.destroy = ezfs_fuse_destroy;
    operations.getattr = ezfs_fuse_getattr;
    operations.readdir = ezfs_fuse_readdir;
    operations.open = ezfs_fuse_open;
    operations.read = ezfs_fuse_read;
    operations.release = ezfs_fuse_release;
    return fuse_main(argc, argv, &operations, NULL);
}
