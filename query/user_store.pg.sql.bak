-- name: GetUserStores :many
select * from user_store where userId = $1;

-- name: AddStoreToUser :exec
insert into user_store (userId, storeId) values ($1, $2);

-- name: CalculatePages :one
SELECT CEIL(COUNT(fs.fileId)::float / $1) AS total_pages
FROM file_store fs
JOIN user_store us ON fs.storeId = us.storeId
WHERE us.userId = $2 AND fs.storeId = $3;

-- name: RemoveStoreFromUser :exec
delete from user_store where userId = $1 and storeId = $2;
