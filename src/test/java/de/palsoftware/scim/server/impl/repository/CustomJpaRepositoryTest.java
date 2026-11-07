package de.palsoftware.scim.server.impl.repository;

import de.palsoftware.scim.server.impl.model.ScimUser;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.support.JpaEntityInformation;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@SuppressWarnings({"unchecked", "rawtypes"})
class CustomJpaRepositoryTest {

    private EntityManager entityManager;
    private CriteriaBuilder cb;
    private CriteriaQuery<ScimUser> query;
    private Root<ScimUser> root;
    private TypedQuery<ScimUser> typedQuery;
    private TestableCustomJpaRepository repository;

    private static class TestableCustomJpaRepository extends CustomJpaRepository<ScimUser, UUID> {
        TestableCustomJpaRepository(JpaEntityInformation<ScimUser, ?> entityInfo, EntityManager em) {
            super(entityInfo, em);
        }

        TypedQuery<ScimUser> buildSortedQuery(Sort sort) {
            return getQuery(null, ScimUser.class, sort);
        }
    }

    @BeforeEach
    void setUp() {
        entityManager = mock(EntityManager.class);
        cb = mock(CriteriaBuilder.class);
        query = mock(CriteriaQuery.class);
        root = mock(Root.class);
        typedQuery = mock(TypedQuery.class);
        JpaEntityInformation<ScimUser, UUID> entityInfo = mock(JpaEntityInformation.class);
        when(entityInfo.getJavaType()).thenReturn(ScimUser.class);
        when(entityManager.getDelegate()).thenReturn(entityManager);
        when(entityManager.getEntityManagerFactory()).thenReturn(mock(EntityManagerFactory.class));

        when(entityManager.getCriteriaBuilder()).thenReturn(cb);
        when(cb.createQuery(ScimUser.class)).thenReturn(query);
        when(query.from(ScimUser.class)).thenReturn(root);
        when(query.select(any())).thenReturn(query);
        when(entityManager.createQuery(query)).thenReturn(typedQuery);

        CriteriaBuilder.Case<Object> caseBuilder = mock(CriteriaBuilder.Case.class);
        Expression<Object> caseExpr = mock(Expression.class);
        when(cb.selectCase()).thenReturn(caseBuilder);
        when(caseBuilder.when(any(Expression.class), any(Object.class))).thenReturn(caseBuilder);
        when(caseBuilder.otherwise(any(Object.class))).thenReturn(caseExpr);
        when(cb.isNull(any())).thenReturn(mock(Predicate.class));

        repository = new TestableCustomJpaRepository(entityInfo, entityManager);
    }

    @Test
    void getQuery_withNullsLastAndIgnoreCase_appliesLowerExpressionToStringAttribute() {
        Path displayNamePath = mock(Path.class);
        when(displayNamePath.getJavaType()).thenReturn(String.class);
        Path idPath = mock(Path.class);
        when(idPath.getJavaType()).thenReturn(UUID.class);
        when(root.get("displayName")).thenReturn(displayNamePath);
        when(root.get("id")).thenReturn(idPath);

        Expression<String> lowerDisplayName = mock(Expression.class);
        when(cb.lower(displayNamePath)).thenReturn(lowerDisplayName);

        Order nullCaseOrder = mock(Order.class);
        Order lowerAscOrder = mock(Order.class);
        Order idAscOrder = mock(Order.class);
        when(cb.asc(any())).thenReturn(nullCaseOrder);
        when(cb.asc(lowerDisplayName)).thenReturn(lowerAscOrder);
        when(cb.asc(idPath)).thenReturn(idAscOrder);

        Sort sort = Sort.by(
                Sort.Order.asc("displayName").nullsLast().ignoreCase(),
                Sort.Order.asc("id")
        );

        TypedQuery<ScimUser> result = repository.buildSortedQuery(sort);

        assertThat(result).isSameAs(typedQuery);
        verify(cb).lower(displayNamePath);
        verify(cb).asc(lowerDisplayName);
        verify(cb, never()).asc(displayNamePath);
        verify(cb, never()).lower((Expression) idPath);
        verify(query).orderBy(any(List.class));
    }

    @Test
    void getQuery_withNullsFirstDescendingAndIgnoreCase_appliesLowerExpressionDesc() {
        Path userNamePath = mock(Path.class);
        when(userNamePath.getJavaType()).thenReturn(String.class);
        when(root.get("userName")).thenReturn(userNamePath);

        Expression<String> lowerUserName = mock(Expression.class);
        when(cb.lower(userNamePath)).thenReturn(lowerUserName);

        Sort sort = Sort.by(Sort.Order.desc("userName").nullsFirst().ignoreCase());

        repository.buildSortedQuery(sort);

        verify(cb).lower(userNamePath);
        verify(cb).desc(lowerUserName);
        verify(cb, never()).desc(userNamePath);
    }

    @Test
    void getQuery_withCaseExactStringAttribute_doesNotApplyLowerExpression() {
        Path externalIdPath = mock(Path.class);
        when(externalIdPath.getJavaType()).thenReturn(String.class);
        when(root.get("externalId")).thenReturn(externalIdPath);

        Sort sort = Sort.by(Sort.Order.asc("externalId").nullsLast());

        repository.buildSortedQuery(sort);

        verify(cb, never()).lower(any());
        verify(cb).asc(externalIdPath);
    }
}
