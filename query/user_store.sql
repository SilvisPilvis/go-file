-- name: GetUserStores :many
select * from user_store where userId = ?;

-- name: AddStoreToUser :exec
insert into user_store (userId, storeId) values (?, ?);

-- name: CalculatePages :one
SELECT CEIL(CAST(COUNT(fs.fileId) AS REAL) / ?) AS total_pages
FROM file_store fs
JOIN user_store us ON fs.storeId = us.storeId
WHERE us.userId = ? AND fs.storeId = ?;

-- name: RemoveStoreFromUser :exec
delete from user_store where userId = ? and storeId = ?;
