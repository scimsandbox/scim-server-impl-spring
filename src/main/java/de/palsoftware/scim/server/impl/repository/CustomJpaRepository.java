package de.palsoftware.scim.server.impl.repository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.*;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.support.JpaEntityInformation;
import org.springframework.data.jpa.repository.support.SimpleJpaRepository;
import org.springframework.lang.Nullable;

import java.util.ArrayList;
import java.util.List;

/**
 * Custom base repository adding criteria support for Sort.NullHandling.NULLS_FIRST and NULLS_LAST,
 * which standard Spring Data JPA QueryUtils throws UnsupportedOperationException for prior to JPA 3.2.
 */
public class CustomJpaRepository<T, ID> extends SimpleJpaRepository<T, ID> {

    private final EntityManager entityManager;

    public CustomJpaRepository(JpaEntityInformation<T, ?> entityInformation, EntityManager entityManager) {
        super(entityInformation, entityManager);
        this.entityManager = entityManager;
    }

    public CustomJpaRepository(Class<T> domainClass, EntityManager entityManager) {
        super(domainClass, entityManager);
        this.entityManager = entityManager;
    }

    @Override
    protected <S extends T> TypedQuery<S> getQuery(@Nullable Specification<S> spec, Class<S> domainClass, Sort sort) {
        boolean hasNullHandling = false;
        if (sort.isSorted()) {
            for (Sort.Order order : sort) {
                if (order.getNullHandling() == Sort.NullHandling.NULLS_FIRST
                        || order.getNullHandling() == Sort.NullHandling.NULLS_LAST) {
                    hasNullHandling = true;
                    break;
                }
            }
        }

        if (!hasNullHandling) {
            return super.getQuery(spec, domainClass, sort);
        }

        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<S> query = builder.createQuery(domainClass);

        Root<S> root = query.from(domainClass);
        if (spec != null) {
            Predicate predicate = spec.toPredicate(root, query, builder);
            if (predicate != null) {
                query.where(predicate);
            }
        }
        query.select(root);

        List<Order> jpaOrders = new ArrayList<>();
        for (Sort.Order order : sort) {
            Path<?> path = getPath(root, order.getProperty());
            boolean isAscending = order.isAscending();
            Sort.NullHandling nullHandling = order.getNullHandling();

            if (nullHandling == Sort.NullHandling.NULLS_LAST) {
                jpaOrders.add(builder.asc(builder.selectCase().when(builder.isNull(path), 1).otherwise(0)));
                jpaOrders.add(isAscending ? builder.asc(path) : builder.desc(path));
            } else if (nullHandling == Sort.NullHandling.NULLS_FIRST) {
                jpaOrders.add(builder.asc(builder.selectCase().when(builder.isNull(path), 0).otherwise(1)));
                jpaOrders.add(isAscending ? builder.asc(path) : builder.desc(path));
            } else {
                jpaOrders.add(isAscending ? builder.asc(path) : builder.desc(path));
            }
        }
        query.orderBy(jpaOrders);

        return entityManager.createQuery(query);
    }

    private Path<?> getPath(Root<?> root, String property) {
        String[] parts = property.split("\\.");
        Path<?> path = root;
        for (String part : parts) {
            path = path.get(part);
        }
        return path;
    }
}
